//! XDF container access and LuaJIT bytecode inspection.
//!
//! The shipping `LuaScripts.xdf` (and sibling `.xdf` packs) are ZIP
//! containers. The shipping pack uses stored (uncompressed) entries with no
//! encryption; patch packs fetched at runtime may use compression, and the
//! client's own ZipFile layer refuses AES entries ("AES encrypted XDF zip
//! entries are not supported") - so deflate and stored cover what the game
//! itself will accept.
//!
//! Lua modules inside are compiled LuaJIT 2.x bytecode (magic `\x1bLJ`),
//! not source. [`LuaJitChunk`] validates the header, surfaces the embedded
//! chunk name (which leaks the build path), and extracts the printable
//! constant strings - the field names, URLs, and protocol tokens the
//! compiled code references - which is how the login-flow field names in
//! this crate were recovered.

use std::fs;
use std::io::{Read, Seek};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{io_error, NetworkError};

/// One entry inside an XDF container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XdfEntry {
    /// Archive-relative name, e.g. `xfs/luascripts/Entities/LoginAgent.lua`.
    pub name: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
}

/// Read+Seek object-safe wrapper so file-backed and in-memory containers
/// share one type.
trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

/// A readable XDF (ZIP) container.
pub struct XdfContainer {
    path: std::path::PathBuf,
    zip: zip::ZipArchive<Box<dyn ReadSeek>>,
}

impl XdfContainer {
    /// Open an XDF container from disk.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, NetworkError> {
        let path = path.as_ref().to_path_buf();
        let file = fs::File::open(&path).map_err(|source| io_error(&path, source))?;
        let zip = zip::ZipArchive::new(Box::new(file) as Box<dyn ReadSeek>)
            .map_err(|source| NetworkError::Xdf(format!("{}: {source}", path.display())))?;
        Ok(Self { path, zip })
    }

    /// Parse a container from an in-memory buffer.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, NetworkError> {
        let cursor = std::io::Cursor::new(bytes);
        let zip = zip::ZipArchive::new(Box::new(cursor) as Box<dyn ReadSeek>)
            .map_err(|source| NetworkError::Xdf(source.to_string()))?;
        Ok(Self {
            path: std::path::PathBuf::new(),
            zip,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of entries in the container.
    pub fn len(&self) -> usize {
        self.zip.len()
    }

    /// Always false; containers have at least one entry.
    pub fn is_empty(&self) -> bool {
        self.zip.len() == 0
    }

    /// List all entries.
    pub fn entries(&mut self) -> Result<Vec<XdfEntry>, NetworkError> {
        let mut out = Vec::with_capacity(self.zip.len());
        for index in 0..self.zip.len() {
            let entry = self
                .zip
                .by_index_raw(index)
                .map_err(|source| NetworkError::Xdf(source.to_string()))?;
            out.push(XdfEntry {
                name: entry.name().to_string(),
                compressed_size: entry.compressed_size(),
                uncompressed_size: entry.size(),
            });
        }
        Ok(out)
    }

    /// Entries whose name contains `needle` (case-insensitive).
    pub fn find(&mut self, needle: &str) -> Result<Vec<XdfEntry>, NetworkError> {
        let needle = needle.to_ascii_lowercase();
        Ok(self
            .entries()?
            .into_iter()
            .filter(|entry| entry.name.to_ascii_lowercase().contains(&needle))
            .collect())
    }

    /// Read one entry fully into memory by exact name.
    pub fn read(&mut self, name: &str) -> Result<Vec<u8>, NetworkError> {
        let mut entry = self
            .zip
            .by_name(name)
            .map_err(|source| NetworkError::Xdf(format!("{name}: {source}")))?;
        let mut buffer = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut buffer)
            .map_err(|source| NetworkError::Xdf(format!("{name}: {source}")))?;
        Ok(buffer)
    }

    /// Read one entry and parse it as a LuaJIT chunk.
    pub fn read_lua_chunk(&mut self, name: &str) -> Result<LuaJitChunk, NetworkError> {
        LuaJitChunk::parse(self.read(name)?)
    }
}

/// A parsed LuaJIT 2.x bytecode chunk header plus its printable constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LuaJitChunk {
    /// Version byte (0x01 = LuaJIT 2.0 bytecode, 0x02 = 2.1+).
    pub version: u8,
    /// Chunk flags (`0x02` = stripped chunk: no debug info).
    pub flags: u8,
    /// The embedded chunk name (source path at compile time).
    pub chunk_name: Option<String>,
    /// Printable ASCII runs (>= `min_string_len`) found in the chunk,
    /// including the constant table's strings.
    pub strings: Vec<String>,
}

impl LuaJitChunk {
    /// LuaJIT bytecode magic: `ESC "LJ"`.
    pub const MAGIC: [u8; 3] = [0x1b, b'L', b'J'];

    /// Validate the header of a LuaJIT bytecode buffer and collect strings.
    pub fn parse(bytes: Vec<u8>) -> Result<Self, NetworkError> {
        if bytes.len() < 6 || bytes[..3] != Self::MAGIC {
            return Err(NetworkError::NotLuaJit(format!(
                "bad magic: {:02x?}",
                bytes.get(..3).unwrap_or(&[])
            )));
        }
        let version = bytes[3];
        if !(1..=2).contains(&version) {
            return Err(NetworkError::NotLuaJit(format!(
                "unsupported bytecode version {version:#x}"
            )));
        }
        // LuaJIT dump header: ESC "LJ" version flags, then (unless stripped)
        // a ULEB128 length-prefixed chunk name.
        let flags = bytes[4];
        let chunk_name = read_uleb_string(&bytes[5..]);
        let strings = extract_strings(&bytes);
        Ok(Self {
            version,
            flags,
            chunk_name,
            strings,
        })
    }

    /// `true` when the chunk carries no debug info.
    pub fn is_stripped(&self) -> bool {
        self.flags & 0x02 != 0
    }
}

/// LuaJIT strings are ULEB128 length-prefixed; used only for the chunk name
/// directly after the flags byte.
fn read_uleb_string(bytes: &[u8]) -> Option<String> {
    let (length, rest) = uleb128(bytes)?;
    let length = usize::try_from(length).ok()?;
    if length == 0 || rest.len() < length {
        return None;
    }
    Some(String::from_utf8_lossy(&rest[..length]).into_owned())
}

fn uleb128(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let mut value: u64 = 0;
    let mut shift = 0;
    for (index, &byte) in bytes.iter().enumerate() {
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, &bytes[index + 1..]));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    None
}

/// Pull printable runs the way `strings(1)` does; LuaJIT constant strings
/// survive in the bytecode regardless of stripping.
fn extract_strings(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (index, &byte) in bytes.iter().enumerate() {
        let printable = (0x20..0x7f).contains(&byte);
        match (start, printable) {
            (None, true) => start = Some(index),
            (Some(begin), false) => {
                if index - begin >= 4 {
                    out.push(String::from_utf8_lossy(&bytes[begin..index]).into_owned());
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(begin) = start {
        if bytes.len() - begin >= 4 {
            out.push(String::from_utf8_lossy(&bytes[begin..]).into_owned());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn build_xdf() -> Vec<u8> {
        let mut buffer = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(&mut buffer);
        let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer
            .start_file("xfs/luascripts/Test.lua", options)
            .unwrap();
        writer
            .write_all(b"\x1bLJ\x02\x08\x08LoginAgent.lua\x00\x01\x02game_server_login")
            .unwrap();
        writer.finish().unwrap();
        buffer.into_inner()
    }

    #[test]
    fn reads_entries_and_lua_chunks() {
        let mut xdf = XdfContainer::from_bytes(build_xdf()).unwrap();
        assert_eq!(xdf.len(), 1);
        let entries = xdf.entries().unwrap();
        assert_eq!(entries[0].name, "xfs/luascripts/Test.lua");

        let chunk = xdf.read_lua_chunk("xfs/luascripts/Test.lua").unwrap();
        assert_eq!(chunk.version, 2);
        assert!(!chunk.is_stripped());
        assert!(chunk
            .strings
            .iter()
            .any(|s| s.contains("game_server_login")));
    }

    #[test]
    fn rejects_non_luajit_payloads() {
        let err = LuaJitChunk::parse(b"plain text".to_vec()).unwrap_err();
        assert!(matches!(err, NetworkError::NotLuaJit(_)));
    }
}
