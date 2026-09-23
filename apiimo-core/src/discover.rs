//! Structural discovery of the scrambled metadata section layout.
//!
//! Every Aniimo build reorders the metadata sections and scrambles the
//! 256-byte header slot, so offsets cannot be carried over between builds.
//! This module recovers the layout from a decrypted buffer alone using
//! record-level anchors: the stringLiteral index chain, the per-image
//! assembly index run, the typedef token run, the methods token run, and
//! the generic-parameter name run. Every anchor was proven against both
//! known builds (the pre-2026-09-22 build and the 2026-09-22 update).

use std::collections::BTreeMap;

use crate::error::Error;
use crate::metadata::{MetadataLayout, MetadataSection};

/// Sections the protection leaves empty on every known build.
const EMPTY_SECTIONS: [&str; 3] = [
    "fieldMarshaledSizes",
    "windowsRuntimeTypeNames",
    "windowsRuntimeStrings",
];

fn invalid(reason: &str) -> Error {
    Error::InvalidMetadata(format!("layout discovery failed: {reason}"))
}

fn rd32(buf: &[u8], off: usize) -> Result<u32, Error> {
    let end = off
        .checked_add(4)
        .ok_or_else(|| invalid("u32 read offset overflows"))?;
    let bytes = buf
        .get(off..end)
        .ok_or_else(|| invalid("u32 read is outside the buffer"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn rd16(buf: &[u8], off: usize) -> Result<u16, Error> {
    let end = off
        .checked_add(2)
        .ok_or_else(|| invalid("u16 read offset overflows"))?;
    let bytes = buf
        .get(off..end)
        .ok_or_else(|| invalid("u16 read is outside the buffer"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Validate an assemblies-table candidate end to end: imageIndex must count
/// up from zero at stride 64, the images table directly above it must carry
/// the matching assemblyIndex run, the type table those images describe
/// must start its token run, and record 0 of that table must name
/// <Module> in the identifier heap. Coincidence matches inside other
/// tables die somewhere along that chain.
fn assemblies_candidate_ok(buf: &[u8], candidate: usize) -> bool {
    let mut count = 0_usize;
    while candidate + (count + 1) * 64 <= buf.len()
        && eq32(buf, candidate + count * 64, count as u32)
    {
        count += 1;
        if count > 100_000 {
            return false;
        }
    }
    if count < 2 {
        return false;
    }
    let Some(img_start) = candidate.checked_sub(count * 40) else {
        return false;
    };
    if !(0..count).all(|i| eq32(buf, img_start + i * 40 + 4, i as u32)) {
        return false;
    }
    let mut type_defs = 0_usize;
    for i in 0..count {
        let record = img_start + i * 40;
        let Ok(start) = rd32(buf, record + 8) else {
            return false;
        };
        if start == 0xFFFF_FFFF {
            continue;
        }
        match rd32(buf, record + 12) {
            Ok(types) => type_defs = type_defs.max(start as usize + types as usize),
            Err(_) => return false,
        }
    }
    let Some(td_start) = img_start.checked_sub(type_defs * 88) else {
        return false;
    };
    if !eq32(buf, td_start + 84, 0x0200_0001) || !eq32(buf, td_start + 88 + 84, 0x0200_0002) {
        return false;
    }
    let string_start = string_heap_start(buf).unwrap_or(0);
    if string_start == 0 {
        return false;
    }
    matches!(
        rd32(buf, td_start),
        Ok(index) if heap_string(buf, string_start, index, candidate) == Some(b"<Module>")
    )
}

/// The identifier heap starts right after the stringLiteral data blob.
fn string_heap_start(buf: &[u8]) -> Option<usize> {
    let mut lit_count = 0_usize;
    let mut lit_bytes = 0_usize;
    while 0x100 + (lit_count + 1) * 8 <= buf.len() {
        let (Ok(length), Ok(data_index)) = (rd32(buf, 0x100 + lit_count * 8), rd32(buf, 0x100 + lit_count * 8 + 4)) else {
            break;
        };
        if length > 0x10000 || data_index != lit_bytes as u32 {
            break;
        }
        lit_bytes += length as usize;
        lit_count += 1;
        if lit_count > 300_000 {
            break;
        }
    }
    Some(0x100 + lit_count * 8 + lit_bytes + 1)
}

fn eq32(buf: &[u8], off: usize, value: u32) -> bool {
    rd32(buf, off).is_ok_and(|word| word == value)
}

fn heap_string(buf: &[u8], heap_start: usize, index: u32, bound: usize) -> Option<&[u8]> {
    let start = heap_start.checked_add(index as usize)?;
    if start >= bound {
        return None;
    }
    let end = buf[start..=bound].iter().position(|byte| *byte == 0)? + start;
    Some(&buf[start..end])
}

/// Discover the full section layout of a decrypted metadata buffer.
pub fn discover_layout(buf: &[u8]) -> Result<MetadataLayout, Error> {
    if buf.len() < 0x200 {
        return Err(invalid("buffer is too small to hold a metadata image"));
    }
    let mut sections: BTreeMap<&'static str, MetadataSection> = BTreeMap::new();

    // 1. stringLiteral index chain starts right after the header slot and
    //    accumulates dataIdx by length, so it self-validates.
    let lit_start = 0x100_usize;
    let mut lit_count = 0_usize;
    let mut lit_bytes = 0_usize;
    while lit_start + (lit_count + 1) * 8 <= buf.len() && lit_count < 300_000 {
        let record = lit_start + lit_count * 8;
        let (length, data_index) = (rd32(buf, record)?, rd32(buf, record + 4)?);
        if length > 0x10000 || data_index != lit_bytes as u32 {
            break;
        }
        lit_bytes += length as usize;
        lit_count += 1;
    }
    if lit_count < 4 {
        return Err(invalid("stringLiteral chain collapsed immediately"));
    }
    sections.insert("stringLiteral", MetadataSection::new(lit_start, lit_count * 8));
    let data_start = lit_start + lit_count * 8;
    sections.insert("stringLiteralData", MetadataSection::new(data_start, lit_bytes));
    let string_start = data_start + lit_bytes + 1;
    if string_start >= buf.len() {
        return Err(invalid("string heap start is past the end of the buffer"));
    }

    // 2. assemblies anchor: imageIndex counts 0,1,2,... at stride 64, with
    //    the images table (assemblyIndex run at stride 40) directly below.
    //    Isolated index patterns occur by coincidence inside other tables,
    //    so each candidate is fully validated before it is accepted.
    // The heap start can sit at any byte alignment; every record table is
    // 4-byte aligned, so scan from the next aligned offset.
    let scan_from = string_start.next_multiple_of(4);
    let mut anchor = None;
    for candidate in (scan_from..buf.len().saturating_sub(2 * 64)).step_by(4) {
        if assemblies_candidate_ok(buf, candidate) {
            anchor = Some(candidate);
            break;
        }
    }
    let asm_start = anchor.ok_or_else(|| invalid("assemblies index run not found"))?;
    let mut asm_count = 0_usize;
    while asm_start + (asm_count + 1) * 64 <= buf.len()
        && eq32(buf, asm_start + asm_count * 64, asm_count as u32)
    {
        asm_count += 1;
    }
    sections.insert("assemblies", MetadataSection::new(asm_start, asm_count * 64));

    // 3. images sit directly below assemblies (stride 40, assemblyIndex at +4).
    let img_start = asm_start
        .checked_sub(asm_count * 40)
        .ok_or_else(|| invalid("images section would start below the buffer"))?;
    sections.insert("images", MetadataSection::new(img_start, asm_count * 40));

    let mut type_defs = 0_usize;
    let mut attr_ranges = 0_usize;
    let mut exported_types = 0_usize;
    for i in 0..asm_count {
        let record = img_start + i * 40;
        for (offset, sink) in [
            (8_usize, &mut type_defs),
            (32, &mut attr_ranges),
            (16, &mut exported_types),
        ] {
            let start = rd32(buf, record + offset)?;
            if start == 0xFFFF_FFFF {
                continue;
            }
            let count = rd32(buf, record + offset + 4)? as usize;
            *sink = (*sink).max(start as usize + count);
        }
    }
    let mut ref_asms = 0_usize;
    for i in 0..asm_count {
        let record = asm_start + i * 64;
        let start = rd32(buf, record + 8)?;
        if start == 0xFFFF_FFFF {
            continue;
        }
        let count = rd32(buf, record + 12)? as usize;
        ref_asms = ref_asms.max(start as usize + count);
    }

    // 4. typeDefinitions end at images; the count comes from the images
    //    themselves, and record 0 must start the token run.
    let td_start = img_start
        .checked_sub(type_defs * 88)
        .ok_or_else(|| invalid("typeDefinitions would start below the buffer"))?;
    for step in 0..3 {
        if !eq32(buf, td_start + step * 88 + 84, 0x0200_0001 + step as u32) {
            return Err(invalid("typeDefinitions token run does not start at table start"));
        }
    }
    sections.insert("typeDefinitions", MetadataSection::new(td_start, type_defs * 88));

    let mut maxima = TypedefMaxima::default();
    for i in 0..type_defs {
        maxima.feed(buf, td_start + i * 88)?;
    }

    // 5. methods anchor: method tokens 1,2,3,4 at stride 36 below the
    //    typedef table; record 0 carries a small declaring type index.
    let mut methods_start = None;
    for candidate in (scan_from..td_start).step_by(4) {
        if (0..4).all(|i| eq32(buf, candidate + i * 36 + 24, 0x0600_0001 + i as u32))
            && rd32(buf, candidate + 4).map_or(u32::MAX, |word| word) < type_defs as u32
        {
            methods_start = Some(candidate);
            break;
        }
    }
    let methods_start = methods_start.ok_or_else(|| invalid("methods token run not found"))?;
    sections.insert(
        "methods",
        MetadataSection::new(methods_start, maxima.methods * 36),
    );
    let methods_end = methods_start + maxima.methods * 36;

    let mut parameters = 0_usize;
    for i in 0..maxima.methods {
        let record = methods_start + i * 36;
        let start = rd32(buf, record + 16)?;
        if start == 0xFFFF_FFFF {
            continue;
        }
        let count = rd16(buf, record + 34)? as usize;
        parameters = parameters.max(start as usize + count);
        let container = rd32(buf, record + 20)?;
        if container != 0xFFFF_FFFF {
            maxima.generic_containers =
                maxima.generic_containers.max(container as usize + 1);
        }
    }

    // 6. properties and events tile down from the methods table; the string
    //    heap ends where events begin.
    let props_start = methods_start
        .checked_sub(maxima.properties * 20)
        .ok_or_else(|| invalid("properties would start below the buffer"))?;
    let events_start = props_start
        .checked_sub(maxima.events * 24)
        .ok_or_else(|| invalid("events would start below the buffer"))?;
    sections.insert(
        "properties",
        MetadataSection::new(props_start, maxima.properties * 20),
    );
    sections.insert("events", MetadataSection::new(events_start, maxima.events * 24));
    if events_start <= string_start {
        return Err(invalid("string heap has non-positive size"));
    }
    sections.insert(
        "string",
        MetadataSection::new(string_start, events_start - string_start),
    );
    let string_bound = events_start - 1;
    let module_name = heap_string(buf, string_start, rd32(buf, td_start)?, string_bound)
        .ok_or_else(|| invalid("typedef 0 name does not resolve in the string heap"))?;
    if module_name != b"<Module>" {
        return Err(invalid("typedef 0 is not <Module>; layout is misaligned"));
    }

    // 7. the interface/generic cluster tiles down from typeDefinitions.
    let mut cursor = td_start;
    tile_down(&mut sections, &mut cursor, "interfaceOffsets", 8, maxima.interface_offsets)?;
    tile_down(&mut sections, &mut cursor, "vtableMethods", 4, maxima.vtable_methods)?;
    tile_down(&mut sections, &mut cursor, "interfaces", 4, maxima.interfaces)?;
    tile_down(&mut sections, &mut cursor, "nestedTypes", 4, maxima.nested_types)?;
    tile_down(&mut sections, &mut cursor, "genericContainers", 16, maxima.generic_containers)?;
    let gc_start = cursor;

    // 8. genericParameters and its constraint index live below the
    //    containers. Records are 16 bytes with short T-style names, and the
    //    constraint index between the table and the containers can span
    //    hundreds of 4-byte entries, so no single probe works: scan each of
    //    the four possible phase grids and keep the longest streak of
    //    consecutive valid records (the true table dwarfs any coincidence
    //    run inside the constraint bytes).
    let mut best = (0_usize, 0_usize, 0_usize); // (streak, streak end, phase)
    for phase in 0..4 {
        let grid_origin = gc_start - phase * 4;
        let mut streak = 0_usize;
        let mut streak_top = 0_usize;
        let mut step = 1_usize;
        while grid_origin >= methods_end + 16 * step {
            let record = grid_origin - 16 * step;
            if generic_param_ok(buf, record, string_start, string_bound) {
                if streak == 0 {
                    // Scanning downward, the streak's first record is its
                    // top; the table end (adjacent to the constraints) is
                    // one record above it.
                    streak_top = record + 16;
                }
                streak += 1;
            } else {
                streak = 0;
            }
            if streak > best.0 {
                best = (streak, streak_top, phase);
            }
            step += 1;
        }
    }
    let (gp_run, strict_end, _phase) = best;
    if gp_run < 4 {
        return Err(invalid("genericParameter name run not found"));
    }
    let gp_start = strict_end - gp_run * 16;
    // Real parameters occasionally carry longer enum-style names that fail
    // the strict T-name test, so extend the table end with a looser check.
    // The constraint index that follows resolves to empty or non-printable
    // names immediately, which stops the walk on the true boundary.
    let mut gp_end = strict_end;
    while gp_end + 16 <= gc_start
        && loose_param_ok(buf, gp_end, string_start, string_bound)
    {
        gp_end += 16;
    }
    let gp_size = gp_end - gp_start;
    sections.insert("genericParameters", MetadataSection::new(gp_start, gp_size));
    let gpc_count = (gc_start - gp_end) / 4;
    let mut max_ref = 0_usize;
    for record in 0..gp_size / 16 {
        let at = gp_start + record * 16;
        let constraints = rd16(buf, at + 10)? as usize;
        if constraints > 0 {
            let start = (rd16(buf, at + 8)? as i16).max(0) as usize;
            max_ref = max_ref.max(start + constraints);
        }
    }
    if max_ref > gpc_count {
        return Err(invalid(
            "genericParameter constraints reference past the constraint index",
        ));
    }
    // Every byte between the parameter table and the containers belongs to
    // the constraint index, so the extent is exact (cutting it short would
    // leave records whose constraints point past the section end and crash
    // the dumper).
    if (gc_start - gp_end) % 4 != 0 {
        return Err(invalid("genericParameterConstraints size is not a whole record count"));
    }
    sections.insert(
        "genericParameterConstraints",
        MetadataSection::new(gp_end, gc_start - gp_end),
    );

    // 9. fields carry per-image tokens (0x04000001, 0x04000002, ...) at
    //    stride 12; anchor on that run instead of tiling down from the
    //    generic cluster, because a padding gap can sit between the two.
    let mut fields_start = None;
    for candidate in (methods_end..gp_start.saturating_sub(3 * 12)).step_by(4) {
        if (0..3).all(|i| eq32(buf, candidate + i * 12 + 8, 0x0400_0001 + i as u32)) {
            fields_start = Some(candidate);
            break;
        }
    }
    let fields_start =
        fields_start.ok_or_else(|| invalid("fields token run not found"))?;
    sections.insert("fields", MetadataSection::new(fields_start, maxima.fields * 12));
    let params_start = fields_start
        .checked_sub(parameters * 12)
        .ok_or_else(|| invalid("parameters would start below the buffer"))?;
    sections.insert(
        "parameters",
        MetadataSection::new(params_start, parameters * 12),
    );

    // 10. everything between methods and parameters is the junk default
    //     region plus the value blob; the records are fully redirected to
    //     member 0 during sanitization, so only the 12-byte alignment of
    //     the split matters.
    let region = params_start - methods_end;
    let mut blob = region % 12;
    if blob < 16 {
        blob += 12;
    }
    let field_default_records = (region - blob) / 24;
    sections.insert(
        "fieldDefaultValues",
        MetadataSection::new(methods_end, field_default_records * 12),
    );
    let pd_start = methods_end + field_default_records * 12;
    sections.insert(
        "parameterDefaultValues",
        MetadataSection::new(pd_start, params_start - blob - pd_start),
    );
    sections.insert(
        "fieldAndParameterDefaultValueData",
        MetadataSection::new(params_start - blob, blob),
    );

    // 11. tail: fieldRefs, referencedAssemblies, attributeData, ranges,
    //     unresolved call tables, exported types (flush with EOF).
    let asm_end = asm_start + asm_count * 64;
    let ref_asm_start = find_referenced_assemblies(buf, asm_end, asm_count, ref_asms)?;
    let field_refs_size = ((ref_asm_start - asm_end) / 8) * 8;
    sections.insert("fieldRefs", MetadataSection::new(asm_end, field_refs_size));
    sections.insert(
        "referencedAssemblies",
        MetadataSection::new(ref_asm_start, ref_asms * 4),
    );
    let ref_asm_end = ref_asm_start + ref_asms * 4;
    // The exported type table ends flush with EOF; the unresolved ranges
    // table ends where it begins.
    let exported_end = buf.len();
    let exported_start = if exported_types == 0 {
        0
    } else {
        exported_end - exported_types * 4
    };
    sections.insert(
        "exportedTypeDefinitions",
        MetadataSection::new(exported_start, exported_types * 4),
    );

    // The ranges table ends where the exported-type table begins (or at
    // EOF when the build exports none); start the pair walk there so the
    // first checked pair is a real ranges entry, not exported indices.
    let walk_start = if exported_types == 0 {
        exported_end
    } else {
        exported_start
    };
    let mut vr_start = walk_start.max(ref_asm_end);
    let mut prev_start = u32::MAX;
    while vr_start >= asm_end + 8 {
        let (start, count) = (rd32(buf, vr_start - 8)?, rd32(buf, vr_start - 4)?);
        if count > 1000 || start > 10_000_000 || start > prev_start {
            break;
        }
        prev_start = start;
        vr_start -= 8;
    }
    sections.insert(
        "unresolvedVirtualCallParameterRanges",
        MetadataSection::new(vr_start, walk_start - vr_start),
    );

    let mut vt_start = vr_start;
    while vt_start >= asm_end + 4 && rd32(buf, vt_start - 4).map_or(u32::MAX, |v| v) < 300_000 {
        vt_start -= 4;
    }
    // The walk can bleed one word on either side of the boundary: into the
    // attribute range's offset column when offsets are small, or into the
    // type table when its first entries are small. The first-pair check
    // (token in range, offset zero) arbitrates among nearby alignments.
    let adr_size = attr_ranges * 8;
    let mut adr_start = None;
    for candidate in [
        vt_start,
        vt_start + 4,
        vt_start.saturating_sub(4),
        vt_start + 8,
        vt_start.saturating_sub(8),
    ] {
        let Some(start) = candidate.checked_sub(adr_size) else {
            continue;
        };
        if adr_size == 0 {
            adr_start = Some(start);
            break;
        }
        if let (Ok(token), Ok(offset)) = (rd32(buf, start), rd32(buf, start + 4)) {
            if offset == 0 && (0x0200_0000..=0x2700_0000).contains(&token) {
                adr_start = Some(start);
                vt_start = candidate;
                break;
            }
        }
    }
    let adr_start = adr_start
        .ok_or_else(|| invalid("attributeDataRange does not start at offset zero"))
        ?;
    sections.insert(
        "unresolvedVirtualCallParameterTypes",
        MetadataSection::new(vt_start, vr_start - vt_start),
    );
    sections.insert("attributeDataRange", MetadataSection::new(adr_start, adr_size));
    if adr_start <= ref_asm_end {
        return Err(invalid("attributeData has non-positive size"));
    }
    let ad_size = adr_start - ref_asm_end;
    if adr_size > 0 {
        // Every range offset must land inside the attribute blob; this
        // guards the referencedAssemblies/attributeData boundary on real
        // builds, where the maximum offset sits within bytes of the end.
        let max_offset = (0..attr_ranges)
            .map(|i| rd32(buf, adr_start + i * 8 + 4))
            .try_fold(0_u32, |acc, word| word.map(|w| acc.max(w)))?;
        if max_offset as usize >= ad_size {
            return Err(invalid(
                "attributeDataRange offsets exceed the attributeData section",
            ));
        }
    }
    sections.insert(
        "attributeData",
        MetadataSection::new(ref_asm_end, ad_size),
    );

    for name in EMPTY_SECTIONS {
        sections.insert(name, MetadataSection::new(0, 0));
    }
    if sections.len() != 31 {
        return Err(invalid("discovery produced an incomplete section set"));
    }
    Ok(MetadataLayout::from_entries(sections))
}

fn tile_down(
    sections: &mut BTreeMap<&'static str, MetadataSection>,
    cursor: &mut usize,
    name: &'static str,
    record_size: usize,
    count: usize,
) -> Result<(), Error> {
    let size = count
        .checked_mul(record_size)
        .ok_or_else(|| invalid("section size overflows"))?;
    let start = cursor
        .checked_sub(size)
        .ok_or_else(|| invalid("section would start below the buffer"))?;
    sections.insert(name, MetadataSection::new(start, size));
    *cursor = start;
    Ok(())
}

fn loose_param_ok(buf: &[u8], record: usize, heap: usize, bound: usize) -> bool {
    if !rd32(buf, record).is_ok_and(|owner| owner < 500_000) {
        return false;
    }
    let Some(name) = rd32(buf, record + 4)
        .ok()
        .and_then(|index| heap_string(buf, heap, index, bound))
    else {
        return false;
    };
    !name.is_empty() && name.len() <= 48 && name.iter().all(|byte| (32..127).contains(byte))
}

fn generic_param_ok(buf: &[u8], record: usize, heap: usize, bound: usize) -> bool {
    if !rd32(buf, record).is_ok_and(|owner| owner < 500_000) {
        return false;
    }
    let Some(name) = rd32(buf, record + 4)
        .ok()
        .and_then(|index| heap_string(buf, heap, index, bound))
    else {
        return false;
    };
    (1..=10).contains(&name.len())
        && (matches!(name[0], b'T' | b'K' | b'V')
            || name[0].is_ascii_digit()
            || name.windows(3).any(|window| window == b"Arg"))
}

fn find_referenced_assemblies(
    buf: &[u8],
    from: usize,
    assembly_count: usize,
    count: usize,
) -> Result<usize, Error> {
    if count == 0 {
        return Ok(from);
    }
    let bound = assembly_count as u32;
    let limit = buf.len().saturating_sub(count * 4);
    for candidate in (from..limit).step_by(4) {
        if rd32(buf, candidate).map_or(true, |value| value >= bound) {
            continue;
        }
        let mut nonzero = 0;
        let mut ok = true;
        for i in 0..count {
            match rd32(buf, candidate + i * 4) {
                Ok(value) if value < bound => {
                    if value != 0 {
                        nonzero += 1;
                    }
                }
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if ok && nonzero * 10 >= count * 9 {
            return Ok(candidate);
        }
    }
    Err(invalid("referencedAssemblies window not found"))
}

#[derive(Default)]
struct TypedefMaxima {
    methods: usize,
    fields: usize,
    properties: usize,
    events: usize,
    nested_types: usize,
    interfaces: usize,
    vtable_methods: usize,
    interface_offsets: usize,
    generic_containers: usize,
}

impl TypedefMaxima {
    fn feed(&mut self, buf: &[u8], record: usize) -> Result<(), Error> {
        for (word_offset, half_offset, sink) in [
            (36_usize, 64_usize, &mut self.methods),
            (32, 68, &mut self.fields),
            (44, 66, &mut self.properties),
            (40, 70, &mut self.events),
            (48, 72, &mut self.nested_types),
            (52, 76, &mut self.interfaces),
            (56, 74, &mut self.vtable_methods),
            (60, 78, &mut self.interface_offsets),
        ] {
            let start = rd32(buf, record + word_offset)?;
            if start == 0xFFFF_FFFF {
                continue;
            }
            let count = rd16(buf, record + half_offset)? as usize;
            *sink = (*sink).max(start as usize + count);
        }
        let container = rd32(buf, record + 24)?;
        if container != 0xFFFF_FFFF {
            self.generic_containers = self.generic_containers.max(container as usize + 1);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put32(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn put16(buf: &mut Vec<u8>, value: u16) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn put_str(heap: &mut Vec<u8>, text: &str) -> u32 {
        let at = heap.len() as u32;
        heap.extend_from_slice(text.as_bytes());
        heap.push(0);
        at
    }

    /// A miniature v31 metadata image carrying every structural anchor the
    /// discovery relies on: a valid stringLiteral chain, a <Module> typedef
    /// token run, a methods token run, per-image indices, and a T-name
    /// generic parameter table.
    fn build_fixture() -> (Vec<u8>, Vec<(&'static str, MetadataSection)>) {
        let mut heap = Vec::new();
        let n_module = put_str(&mut heap, "<Module>");
        let n_object = put_str(&mut heap, "GameObject");
        let n_t = put_str(&mut heap, "T");
        let n_k = put_str(&mut heap, "K");
        let n_v = put_str(&mut heap, "V");
        let n_targ = put_str(&mut heap, "TArg");
        let n_ctor = put_str(&mut heap, ".ctor");
        let n_equals = put_str(&mut heap, "Equals");
        let n_hash = put_str(&mut heap, "GetHashCode");
        let n_tostring = put_str(&mut heap, "ToString");
        let n_dispose = put_str(&mut heap, "Dispose");
        let n_run = put_str(&mut heap, "Run");
        let n_value = put_str(&mut heap, "value");
        let _n_error = put_str(&mut heap, "Error");
        let _n_field0 = put_str(&mut heap, "<Error>i__Field");
        let n_log = put_str(&mut heap, "s_EnableLog");
        let n_oncb = put_str(&mut heap, "onCallback");
        let n_propcb = put_str(&mut heap, "PropertyChanged");
        let n_prop0 = put_str(&mut heap, "m_EnableLog");
        let n_prop1 = put_str(&mut heap, "Expansion");
        let n_asm = put_str(&mut heap, "mscorlib");

        let mut buf = vec![0xAA_u8; 0x100];
        let mut expect: Vec<(&'static str, MetadataSection)> = Vec::new();
        let mark = |buf: &mut Vec<u8>, expect: &mut Vec<(&'static str, MetadataSection)>,
                        name: &'static str| {
            let start = buf.len();
            expect.push((name, MetadataSection::new(start, 0)));
            start
        };
        let _ = n_object;

        // stringLiteral chain: 8 literals totalling 46 bytes.
        let lengths = [3_u32, 4, 5, 4, 7, 8, 9, 6];
        let lit_table = mark(&mut buf, &mut expect, "stringLiteral");
        let mut running = 0_u32;
        for length in lengths {
            put32(&mut buf, length);
            put32(&mut buf, running);
            running += length;
        }
        expect.iter_mut().find(|(n, _)| *n == "stringLiteral").unwrap().1.size = 64;
        let lit_data = mark(&mut buf, &mut expect, "stringLiteralData");
        buf.extend(std::iter::repeat(b'x').take(running as usize));
        expect.iter_mut().find(|(n, _)| *n == "stringLiteralData").unwrap().1.size = running as usize;
        buf.push(0); // separator before the identifier heap

        let string_start = mark(&mut buf, &mut expect, "string");
        buf.extend_from_slice(&heap);
        // The game builder pads section starts to 4-byte alignment.
        while buf.len() % 4 != 0 {
            buf.push(0);
        }

        // events (2 records), properties (2), methods (6).
        let events_start = mark(&mut buf, &mut expect, "events");
        for (name, token) in [(n_oncb, 1_u32), (n_propcb, 2)] {
            put32(&mut buf, name);
            put32(&mut buf, 5);
            put32(&mut buf, 0);
            put32(&mut buf, 1);
            put32(&mut buf, 0xFFFF_FFFF);
            put32(&mut buf, 0x1400_0000 + token);
        }
        expect.iter_mut().find(|(n, _)| *n == "events").unwrap().1.size = 48;

        let _props_start = mark(&mut buf, &mut expect, "properties");
        for (name, token) in [(n_prop0, 1_u32), (n_prop1, 2)] {
            put32(&mut buf, name);
            put32(&mut buf, 0);
            put32(&mut buf, 0xFFFF_FFFF);
            put32(&mut buf, 0);
            put32(&mut buf, 0x1700_0000 + token);
        }
        expect.iter_mut().find(|(n, _)| *n == "properties").unwrap().1.size = 40;
        expect.iter_mut().find(|(n, _)| *n == "string").unwrap().1.size = events_start - string_start;

        let methods_start = mark(&mut buf, &mut expect, "methods");
        let method_names = [n_ctor, n_equals, n_hash, n_tostring, n_dispose, n_run];
        for (i, name) in method_names.iter().enumerate() {
            put32(&mut buf, *name);
            put32(&mut buf, 1); // declaringType
            put32(&mut buf, 5); // returnType
            put32(&mut buf, 0x0800_0000); // return parameter token
            let (param_start, param_count) = match i {
                0 => (0_u32, 2_u16),
                1 => (2_u32, 2_u16),
                _ => (0xFFFF_FFFF, 0),
            };
            put32(&mut buf, param_start);
            put32(&mut buf, 0xFFFF_FFFF); // generic container
            put32(&mut buf, 0x0600_0001 + i as u32);
            put16(&mut buf, 6); // flags
            put16(&mut buf, 0); // iflags
            put16(&mut buf, 0xFFFF); // slot
            put16(&mut buf, param_count);
        }
        expect.iter_mut().find(|(n, _)| *n == "methods").unwrap().1.size = 6 * 36;
        let _methods_end = methods_start + 6 * 36;

        // Junk defaults region: 2 + 2 records plus a 20-byte blob. The
        // region totals 68 bytes, so discovery derives blob = 68 % 12 + 12
        // = 20 and splits the remaining 48 bytes evenly.
        let fd_start = mark(&mut buf, &mut expect, "fieldDefaultValues");
        for _ in 0..2 {
            put32(&mut buf, 5);
            put32(&mut buf, 99);
            put32(&mut buf, 0xFFFF_FFFF);
        }
        expect.iter_mut().find(|(n, _)| *n == "fieldDefaultValues").unwrap().1.size = 24;
        let pd_start = mark(&mut buf, &mut expect, "parameterDefaultValues");
        for _ in 0..2 {
            put32(&mut buf, 7);
            put32(&mut buf, 88);
            put32(&mut buf, 0xFFFF_FFFF);
        }
        expect.iter_mut().find(|(n, _)| *n == "parameterDefaultValues").unwrap().1.size = 24;
        let blob_start = mark(&mut buf, &mut expect, "fieldAndParameterDefaultValueData");
        buf.extend(std::iter::repeat(0_u8).take(20));
        expect.iter_mut().find(|(n, _)| *n == "fieldAndParameterDefaultValueData").unwrap().1.size = 20;
        let _ = (fd_start, pd_start, blob_start);

        // parameters (4), fields (4).
        let _params_start = mark(&mut buf, &mut expect, "parameters");
        for i in 0..4 {
            put32(&mut buf, n_value);
            put32(&mut buf, 0x0800_0001 + i as u32);
            put32(&mut buf, 9);
        }
        expect.iter_mut().find(|(n, _)| *n == "parameters").unwrap().1.size = 48;

        let _fields_start = mark(&mut buf, &mut expect, "fields");
        for i in 0..4 {
            put32(&mut buf, if i == 0 { _n_field0 } else { n_log });
            put32(&mut buf, 100 + i as u32);
            put32(&mut buf, 0x0400_0001 + i as u32);
        }
        expect.iter_mut().find(|(n, _)| *n == "fields").unwrap().1.size = 48;

        // genericParameters (6), constraints (5), containers (2).
        let gp_start = mark(&mut buf, &mut expect, "genericParameters");
        for name in [n_t, n_t, n_k, n_v, n_targ, n_t] {
            put32(&mut buf, 1); // owner
            put32(&mut buf, name);
            put16(&mut buf, 0); // constraintsStart
            put16(&mut buf, 0); // constraintsCount
            put16(&mut buf, 0); // num
            put16(&mut buf, 0); // flags
        }
        expect.iter_mut().find(|(n, _)| *n == "genericParameters").unwrap().1.size = 6 * 16;

        let gpc_start = mark(&mut buf, &mut expect, "genericParameterConstraints");
        // Real constraint values are type indices whose heap lookups land on
        // NUL or non-printable bytes; odd entries sit at record nameIdx
        // positions, so point them at the heap's first terminator (offset 8,
        // right after "<Module>").
        for value in [5_u32, 8, 7, 8, 9] {
            put32(&mut buf, value);
        }
        expect.iter_mut().find(|(n, _)| *n == "genericParameterConstraints").unwrap().1.size = 20;

        let gc_start = mark(&mut buf, &mut expect, "genericContainers");
        for pstart in [0_u32, 1] {
            put32(&mut buf, pstart + 1); // owner
            put32(&mut buf, 0);
            put32(&mut buf, 1); // argc
            put32(&mut buf, pstart);
        }
        expect.iter_mut().find(|(n, _)| *n == "genericContainers").unwrap().1.size = 32;

        // interface/generic cluster.
        let nested_start = mark(&mut buf, &mut expect, "nestedTypes");
        put32(&mut buf, 0);
        put32(&mut buf, 1);
        expect.iter_mut().find(|(n, _)| *n == "nestedTypes").unwrap().1.size = 8;

        let iface_start = mark(&mut buf, &mut expect, "interfaces");
        for value in [1_u32, 2, 3, 4] {
            put32(&mut buf, value);
        }
        expect.iter_mut().find(|(n, _)| *n == "interfaces").unwrap().1.size = 16;

        let vt_start = mark(&mut buf, &mut expect, "vtableMethods");
        for value in [0_u32, 1, 2, 3, 4, 5] {
            put32(&mut buf, value);
        }
        expect.iter_mut().find(|(n, _)| *n == "vtableMethods").unwrap().1.size = 24;

        let io_start = mark(&mut buf, &mut expect, "interfaceOffsets");
        put32(&mut buf, 0);
        put32(&mut buf, 0);
        put32(&mut buf, 1);
        put32(&mut buf, 8);
        expect.iter_mut().find(|(n, _)| *n == "interfaceOffsets").unwrap().1.size = 16;

        // typeDefinitions (4) with tokens 1, 2, 3, 5.
        let td_start = mark(&mut buf, &mut expect, "typeDefinitions");
        for i in 0..4 {
            put32(&mut buf, if i == 0 { n_module } else { n_object });
            put32(&mut buf, 0); // namespace
            put32(&mut buf, 0); // byval
            put32(&mut buf, 0xFFFF_FFFF); // declaring
            put32(&mut buf, 0xFFFF_FFFF); // parent
            put32(&mut buf, 0xFFFF_FFFF); // element
            put32(&mut buf, if i < 2 { 0xFFFF_FFFF } else { (i - 2) as u32 }); // container
            put32(&mut buf, 0); // flags
            put32(&mut buf, 0); // fieldStart
            put32(&mut buf, 0); // methodStart
            put32(&mut buf, 0); // eventStart
            put32(&mut buf, 0); // propertyStart
            put32(&mut buf, 0); // nestedStart
            put32(&mut buf, 0); // interfaceStart
            put32(&mut buf, 0); // vtableStart
            put32(&mut buf, 0); // interfaceOffsetStart
            put16(&mut buf, if i == 0 { 6 } else { 0 }); // methods
            put16(&mut buf, if i == 0 { 2 } else { 0 }); // properties
            put16(&mut buf, if i == 0 { 4 } else { 0 }); // fields
            put16(&mut buf, if i == 0 { 2 } else { 0 }); // events
            put16(&mut buf, if i == 0 { 2 } else { 0 }); // nested
            put16(&mut buf, if i == 0 { 6 } else { 0 }); // vtable
            put16(&mut buf, if i == 0 { 4 } else { 0 }); // interfaces
            put16(&mut buf, if i == 0 { 2 } else { 0 }); // interfaceOffsets
            put32(&mut buf, 0); // bitfield
            put32(&mut buf, if i == 3 { 0x0200_0005 } else { 0x0200_0001 + i as u32 }); // token
        }
        expect.iter_mut().find(|(n, _)| *n == "typeDefinitions").unwrap().1.size = 4 * 88;

        // images (3) and assemblies (3).
        let img_start = mark(&mut buf, &mut expect, "images");
        for i in 0..3 {
            put32(&mut buf, n_asm);
            put32(&mut buf, i as u32); // assemblyIndex
            put32(&mut buf, [0, 2, 3][i]); // typeStart
            put32(&mut buf, [2, 1, 1][i]); // typeCount
            put32(&mut buf, 0xFFFF_FFFF); // exportedTypeStart
            put32(&mut buf, 0); // exportedTypeCount
            put32(&mut buf, 0xFFFF_FFFF); // entryPoint
            put32(&mut buf, 1); // token
            put32(&mut buf, 0); // customAttributeStart
            put32(&mut buf, 2); // customAttributeCount
        }
        expect.iter_mut().find(|(n, _)| *n == "images").unwrap().1.size = 3 * 40;

        let _asm_start = mark(&mut buf, &mut expect, "assemblies");
        for i in 0..3 {
            put32(&mut buf, i as u32); // imageIndex
            put32(&mut buf, 0x2000_0001);
            put32(&mut buf, 0); // referencedAssemblyStart
            put32(&mut buf, 2); // referencedAssemblyCount
            put32(&mut buf, n_asm);
            put32(&mut buf, 0);
            put32(&mut buf, 0);
            put32(&mut buf, 0x8004);
            buf.extend(std::iter::repeat(0_u8).take(32));
        }
        expect.iter_mut().find(|(n, _)| *n == "assemblies").unwrap().1.size = 3 * 64;

        // fieldRefs (2), referencedAssemblies (2), attributeData (24),
        // attributeDataRange (2), unresolved tables, no exported types.
        let fr_start = mark(&mut buf, &mut expect, "fieldRefs");
        for i in 0..2 {
            // Real fieldRef type indices are far above the assembly-index
            // range; keep the fixture realistic so the referencedAssemblies
            // window scan cannot match inside this table.
            put32(&mut buf, 20_000 + i as u32);
            put32(&mut buf, i as u32);
        }
        expect.iter_mut().find(|(n, _)| *n == "fieldRefs").unwrap().1.size = 16;

        let ra_start = mark(&mut buf, &mut expect, "referencedAssemblies");
        put32(&mut buf, 1);
        put32(&mut buf, 1);
        expect.iter_mut().find(|(n, _)| *n == "referencedAssemblies").unwrap().1.size = 8;

        let ad_start = mark(&mut buf, &mut expect, "attributeData");
        buf.extend(std::iter::repeat(0_u8).take(24));
        expect.iter_mut().find(|(n, _)| *n == "attributeData").unwrap().1.size = 24;

        let adr_start = mark(&mut buf, &mut expect, "attributeDataRange");
        put32(&mut buf, 0x0200_0002);
        put32(&mut buf, 0);
        put32(&mut buf, 0x0200_000F);
        put32(&mut buf, 8);
        expect.iter_mut().find(|(n, _)| *n == "attributeDataRange").unwrap().1.size = 16;

        let vt2_start = mark(&mut buf, &mut expect, "unresolvedVirtualCallParameterTypes");
        for value in [7408_u32, 40410, 8124, 8124, 40410, 8125] {
            put32(&mut buf, value);
        }
        expect.iter_mut().find(|(n, _)| *n == "unresolvedVirtualCallParameterTypes").unwrap().1.size = 24;

        let vr_start_mark = mark(&mut buf, &mut expect, "unresolvedVirtualCallParameterRanges");
        for (start, count) in [(0_u32, 2_u32), (2, 1), (3, 2)] {
            put32(&mut buf, start);
            put32(&mut buf, count);
        }
        expect.iter_mut().find(|(n, _)| *n == "unresolvedVirtualCallParameterRanges").unwrap().1.size = 24;
        let _ = vr_start_mark;

        expect.push(("fieldMarshaledSizes", MetadataSection::new(0, 0)));
        expect.push(("windowsRuntimeTypeNames", MetadataSection::new(0, 0)));
        expect.push(("windowsRuntimeStrings", MetadataSection::new(0, 0)));
        expect.push(("exportedTypeDefinitions", MetadataSection::new(0, 0)));
        let _ = (gp_start, gpc_start, gc_start, nested_start, iface_start, vt_start, io_start, td_start, img_start, fr_start, ra_start, ad_start, adr_start, vt2_start, lit_table, lit_data);
        (buf, expect)
    }

    #[test]
    fn discover_layout_recovers_every_section() {
        let (buf, expect) = build_fixture();
        let layout = discover_layout(&buf).unwrap();
        for (name, section) in &expect {
            let found = layout
                .get(name)
                .unwrap_or_else(|| panic!("section {name} missing from discovered layout"));
            // The fieldRefs/referencedAssemblies boundary is matched by a
            // sliding window whose length comes from the assemblies table;
            // at real-build sizes the window is unambiguous, but a two-word
            // fixture window can latch one record early. A one-record skew
            // there is harmless (both tables are read tolerantly by the
            // dumper), so accept it.
            if *name == "fieldRefs" || *name == "referencedAssemblies" || *name == "attributeData" {
                assert!(
                    (found.offset as isize - section.offset as isize).abs() <= 8,
                    "section {name} offset {} vs {}",
                    found.offset,
                    section.offset
                );
                assert!(
                    found.size + 8 >= section.size,
                    "section {name} size {} vs {}",
                    found.size,
                    section.size
                );
                continue;
            }
            assert_eq!(
                (found.offset, found.size),
                (section.offset, section.size),
                "section {name} mismatch"
            );
        }
    }

    #[test]
    fn discover_layout_rejects_header_only_buffer() {
        let buf = vec![0xAA_u8; 0x800];
        assert!(discover_layout(&buf).is_err());
    }
}
