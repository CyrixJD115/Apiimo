//! Embedded Il2CppDumper management.
//!
//! The self-contained single-file dumper built from the `apiimo-il2cpp`
//! submodule (see `tools/embed-dumper.sh`) is zstd-compressed into
//! `assets/il2cpp-dumper.sfx.zst` and compiled into the binary with
//! `include_bytes!`. On first use it is extracted into a per-build cache
//! directory named after the bundle's FNV-1a-64 hash, so an unchanged
//! build never rewrites disk, and [`ensure_extracted`] returns the path of
//! the ready-to-run executable. The dumper resolves its `config.json`
//! from its own base directory (Program.cs: `AppDomain.BaseDirectory`),
//! so the config is written alongside the extracted binary.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Compressed self-contained Il2CppDumper image; empty placeholder when the
/// embedding script has not been run (fall back to the PATH dumper).
pub const EMBEDDED_BUNDLE_ZST: &[u8] = include_bytes!("../assets/il2cpp-dumper.sfx.zst");
/// The dumper `config.json` shipped with the embedded build.
pub const EMBEDDED_CONFIG_JSON: &[u8] = include_bytes!("../assets/config.json");

/// Errors raised while extracting the embedded dumper.
#[derive(Debug, thiserror::Error)]
pub enum EmbedError {
    #[error("no cache directory is available for extraction")]
    NoCacheDir,
    #[error("failed to decompress the embedded dumper bundle: {0}")]
    Decompress(String),
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// `true` when a real dumper bundle is compiled into this binary.
pub fn embedded_available() -> bool {
    !EMBEDDED_BUNDLE_ZST.is_empty()
}

/// FNV-1a 64-bit hash, used to fingerprint the embedded bundle for cache
/// directory naming (not cryptographic — it only distinguishes builds).
pub fn fnv1a64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Extract the embedded dumper into the cache directory and return the
/// executable path. Returns `Ok(None)` when no bundle is embedded. An
/// existing hash-matching extraction is reused without any disk writes.
pub fn ensure_extracted() -> Result<Option<PathBuf>, EmbedError> {
    if !embedded_available() {
        return Ok(None);
    }

    let cache = cache_dir().ok_or(EmbedError::NoCacheDir)?;
    fs::create_dir_all(&cache).map_err(|source| EmbedError::Io {
        path: cache.clone(),
        source,
    })?;

    let bundle_hash = fnv1a64(EMBEDDED_BUNDLE_ZST);
    let tag = format!("dumper-{bundle_hash:016x}");
    let entry = cache.join(&tag);
    let executable = entry.join(executable_name());
    let config = entry.join("config.json");

    if executable.is_file() && config.is_file() {
        gc_stale_entries(&cache, &tag);
        return Ok(Some(executable));
    }

    // Decompress into a sibling temp directory, then move into place so a
    // crash mid-extraction cannot leave a half-written cache entry that
    // later masquerades as a hit.
    let staging = cache.join(format!(".{tag}.tmp"));
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging).map_err(|source| EmbedError::Io {
        path: staging.clone(),
        source,
    })?;

    let staged_executable = staging.join(executable_name());
    decompress_bundle(&staged_executable)?;
    mark_executable(&staged_executable)?;
    fs::write(staging.join("config.json"), EMBEDDED_CONFIG_JSON).map_err(|source| {
        EmbedError::Io {
            path: staging.clone(),
            source,
        }
    })?;

    let _ = fs::remove_dir_all(&entry);
    fs::rename(&staging, &entry).map_err(|source| EmbedError::Io {
        path: entry.clone(),
        source,
    })?;
    gc_stale_entries(&cache, &tag);
    Ok(Some(executable))
}

/// User cache directory (`XDG_CACHE_HOME`, `~/.cache`, `%LOCALAPPDATA%`,
/// then the temp directory as a last resort), with an `apiimo` subdirectory.
pub fn cache_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_CACHE_HOME") {
        if !dir.is_empty() {
            return Some(PathBuf::from(dir).join("apiimo"));
        }
    }
    if let Some(dir) = std::env::var_os("LOCALAPPDATA") {
        if !dir.is_empty() {
            return Some(PathBuf::from(dir).join("apiimo").join("cache"));
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            return Some(PathBuf::from(home).join(".cache").join("apiimo"));
        }
    }
    Some(std::env::temp_dir().join("apiimo"))
}

fn executable_name() -> &'static str {
    if cfg!(windows) {
        "Il2CppDumper.exe"
    } else {
        "Il2CppDumper"
    }
}

fn decompress_bundle(target: &Path) -> Result<(), EmbedError> {
    let mut decoder = ruzstd::StreamingDecoder::new(EMBEDDED_BUNDLE_ZST)
        .map_err(|error| EmbedError::Decompress(error.to_string()))?;
    let mut plain = Vec::new();
    decoder
        .read_to_end(&mut plain)
        .map_err(|error| EmbedError::Decompress(error.to_string()))?;
    fs::write(target, plain).map_err(|source| EmbedError::Io {
        path: target.to_path_buf(),
        source,
    })
}

fn mark_executable(path: &Path) -> Result<(), EmbedError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(|source| {
            EmbedError::Io {
                path: path.to_path_buf(),
                source,
            }
        })?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Best-effort removal of cache entries from other builds.
fn gc_stale_entries(cache: &Path, keep: &str) {
    let Ok(entries) = fs::read_dir(cache) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with("dumper-") && name != keep {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv_matches_reference_vectors() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x85944171f73967e8);
    }

    #[test]
    fn extraction_is_stable_and_reuses_cache() {
        if !embedded_available() {
            return; // placeholder build: nothing embedded to extract
        }
        let first = ensure_extracted().unwrap().expect("bundle is embedded");
        let second = ensure_extracted().unwrap().expect("bundle is embedded");
        assert_eq!(first, second);
        assert!(first.is_file());
        assert!(first.parent().unwrap().join("config.json").is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = first.metadata().unwrap().permissions().mode();
            assert_eq!(mode & 0o111, 0o111);
        }
    }
}
