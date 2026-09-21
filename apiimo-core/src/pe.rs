use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{io_error, Error};

/// A section in a PE image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeSection {
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_pointer: u32,
    pub raw_size: u32,
}

/// Minimal PE parser used for VA/file-offset conversion and binary patching.
#[derive(Debug, Clone)]
pub struct PeImage {
    path: Option<PathBuf>,
    data: Vec<u8>,
    image_base: u64,
    sections: Vec<PeSection>,
}

impl PeImage {
    /// Parse a PE image from disk.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        let data = fs::read(&path).map_err(|source| io_error(&path, source))?;
        let mut image = Self::from_bytes(data)?;
        image.path = Some(path);
        Ok(image)
    }

    /// Parse a PE image from an in-memory buffer.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, Error> {
        if data.len() < 0x40 {
            return Err(Error::InvalidPe(
                "file is shorter than the DOS header".into(),
            ));
        }

        let pe_offset = read_u32(&data, 0x3c)
            .ok_or_else(|| Error::InvalidPe("missing e_lfanew".into()))?
            as usize;
        if pe_offset.checked_add(24).is_none() || pe_offset + 24 > data.len() {
            return Err(Error::InvalidPe("PE header is outside the file".into()));
        }
        if data[pe_offset..pe_offset + 4] != *b"PE\0\0" {
            return Err(Error::InvalidPe("missing PE signature".into()));
        }

        let number_of_sections = read_u16(&data, pe_offset + 6)
            .ok_or_else(|| Error::InvalidPe("missing section count".into()))?
            as usize;
        let optional_header_size = read_u16(&data, pe_offset + 20)
            .ok_or_else(|| Error::InvalidPe("missing optional-header size".into()))?
            as usize;
        let optional_header = pe_offset + 24;
        let optional_end = optional_header
            .checked_add(optional_header_size)
            .ok_or_else(|| Error::InvalidPe("optional header overflows file".into()))?;
        if optional_end > data.len() {
            return Err(Error::InvalidPe(
                "optional header is outside the file".into(),
            ));
        }

        let magic = read_u16(&data, optional_header)
            .ok_or_else(|| Error::InvalidPe("missing optional-header magic".into()))?;
        let image_base = match magic {
            0x20b => read_u64(&data, optional_header + 24),
            0x10b => read_u32(&data, optional_header + 28).map(u64::from),
            _ => None,
        }
        .ok_or_else(|| Error::InvalidPe("unsupported or truncated optional header".into()))?;

        let section_table = optional_end;
        let section_table_size = number_of_sections
            .checked_mul(40)
            .ok_or_else(|| Error::InvalidPe("section table overflows file".into()))?;
        let section_table_end = section_table
            .checked_add(section_table_size)
            .ok_or_else(|| Error::InvalidPe("section table overflows file".into()))?;
        if section_table_end > data.len() {
            return Err(Error::InvalidPe("section table is outside the file".into()));
        }

        let mut sections = Vec::with_capacity(number_of_sections);
        for index in 0..number_of_sections {
            let offset = section_table + index * 40;
            sections.push(PeSection {
                virtual_size: read_u32(&data, offset + 8).unwrap(),
                virtual_address: read_u32(&data, offset + 12).unwrap(),
                raw_size: read_u32(&data, offset + 16).unwrap(),
                raw_pointer: read_u32(&data, offset + 20).unwrap(),
            });
        }

        Ok(Self {
            path: None,
            data,
            image_base,
            sections,
        })
    }

    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    pub fn sections(&self) -> &[PeSection] {
        &self.sections
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Convert an image VA to a raw file offset.
    pub fn va_to_file_offset(&self, va: u64) -> Option<usize> {
        let rva = va.checked_sub(self.image_base)?;
        self.sections.iter().find_map(|section| {
            let start = u64::from(section.virtual_address);
            let end = start.checked_add(u64::from(section.virtual_size))?;
            if (start..end).contains(&rva) {
                let offset = u64::from(section.raw_pointer).checked_add(rva - start)?;
                usize::try_from(offset).ok()
            } else {
                None
            }
        })
    }

    /// Convert a raw file offset to an image VA.
    pub fn file_offset_to_va(&self, offset: usize) -> Option<u64> {
        let offset = u64::try_from(offset).ok()?;
        self.sections.iter().find_map(|section| {
            let start = u64::from(section.raw_pointer);
            let end = start.checked_add(u64::from(section.raw_size))?;
            if (start..end).contains(&offset) {
                self.image_base
                    .checked_add(u64::from(section.virtual_address))?
                    .checked_add(offset - start)
            } else {
                None
            }
        })
    }

    /// Patch bytes at a mapped VA and persist the file when this image came
    /// from [`Self::from_file`]. In-memory images can still be patched for
    /// testing or a caller can write [`Self::data`] itself.
    pub fn patch(&mut self, va: u64, bytes: &[u8]) -> Result<usize, Error> {
        let offset = self
            .va_to_file_offset(va)
            .ok_or_else(|| Error::InvalidPe(format!("VA {va:#x} is not mapped")))?;
        let end = offset
            .checked_add(bytes.len())
            .ok_or_else(|| Error::InvalidPe("patch exceeds addressable file size".into()))?;
        if end > self.data.len() {
            return Err(Error::InvalidPe(format!(
                "patch at file offset {offset:#x} exceeds file size {:#x}",
                self.data.len()
            )));
        }
        self.data[offset..end].copy_from_slice(bytes);
        if let Some(path) = &self.path {
            fs::write(path, &self.data).map_err(|source| io_error(path, source))?;
        }
        Ok(offset)
    }

    /// Decode hex bytes and patch them at a mapped VA.
    pub fn patch_hex(&mut self, va: u64, hex: &str) -> Result<usize, Error> {
        let bytes = decode_hex(hex)?;
        self.patch(va, &bytes)
    }
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn decode_hex(input: &str) -> Result<Vec<u8>, Error> {
    let compact: Vec<u8> = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if compact.len() % 2 != 0 {
        return Err(Error::InvalidHex(
            "an even number of digits is required".into(),
        ));
    }
    let mut result = Vec::with_capacity(compact.len() / 2);
    for pair in compact.chunks_exact(2) {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| Error::InvalidHex(format!("invalid digit {:?}", pair[0] as char)))?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| Error::InvalidHex(format!("invalid digit {:?}", pair[1] as char)))?;
        result.push(((high << 4) | low) as u8);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_and_patches_a_pe_section() {
        let mut data = vec![0_u8; 0x400];
        data[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        data[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
        data[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());

        let optional = 0x98;
        data[optional..optional + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
        data[optional + 24..optional + 32].copy_from_slice(&0x1_8000_0000_u64.to_le_bytes());

        let section = optional + 0xf0;
        data[section + 8..section + 12].copy_from_slice(&0x2000_u32.to_le_bytes());
        data[section + 12..section + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        data[section + 16..section + 20].copy_from_slice(&0x200_u32.to_le_bytes());
        data[section + 20..section + 24].copy_from_slice(&0x200_u32.to_le_bytes());

        let mut image = PeImage::from_bytes(data).unwrap();
        let va = 0x1_8000_1005_u64;
        assert_eq!(image.va_to_file_offset(va), Some(0x205));
        assert_eq!(image.file_offset_to_va(0x205), Some(va));
        assert_eq!(image.patch_hex(va, "AA bb").unwrap(), 0x205);
        assert_eq!(&image.data()[0x205..0x207], &[0xaa, 0xbb]);
    }
}
