//! CLI and library API facade for Apiimo.
//!
//! This crate is the boundary the outside world talks to: the `apiimo`
//! binary parses the same commands as the original Python tool, and
//! [`Apiimo::run`] returns structured [`Output`] values so a GUI such as
//! AniiStudio (via its `ans-apiimo` bridge) can drive the toolkit without
//! scraping stdout.
//!
//! Layering: `apiimo-api` -> `apiimo-core` -> `apiimo-crypto`, with
//! `apiimo-network` reserved for the future session/profile clients.

#![forbid(unsafe_code)]

mod cli;
mod dumper;
mod error;

pub use cli::{parse, render, usage, CliError, Invocation};
pub use dumper::{
    cache_dir, embedded_available, ensure_extracted, fnv1a64, EmbedError, EMBEDDED_BUNDLE_ZST,
    EMBEDDED_CONFIG_JSON,
};
pub use error::ApiError;

use std::path::PathBuf;

use apiimo_core::{
    default_game_dir, find_addresses, find_classes, find_fields, find_methods, find_strings,
    load_script, output_path, run_dump, AddressMatch, ClassMatch, DumpOptions, DumpReport,
    MethodMatch, PeImage, StringLiteralMatch, TYPES_IN_BINARY,
};
use serde::{Deserialize, Serialize};

/// Result limits mirroring the Python tool's command defaults.
pub mod limits {
    pub const CLASSES: usize = 100;
    pub const METHODS: usize = 60;
    pub const FIELDS: usize = 80;
    pub const ADDRESSES: usize = 20;
    pub const STRINGS: usize = 40;
}

/// One toolkit command, mirroring the Python CLI surface.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Command {
    /// Full decrypt -> rebuild -> sanitize -> Il2CppDumper pipeline.
    Dump,
    /// Experimental string-table section rediscovery.
    Discover,
    /// List classes/structs/interfaces matching a case-insensitive regex.
    Classes { pattern: String, limit: usize },
    /// List methods matching a regex, with resolved addresses.
    Methods { pattern: String, limit: usize },
    /// Print the declaration block of classes matching a regex.
    Fields { pattern: String, limit: usize },
    /// Resolve method addresses from `script.json` by substring.
    Addr { needle: String, limit: usize },
    /// Search string literals by regex.
    Str { pattern: String, limit: usize },
    /// Convert a GameAssembly.dll VA to a file offset.
    Va2Off { va: u64 },
    /// Convert a file offset to a GameAssembly.dll VA.
    Off2Va { offset: u64 },
    /// Patch GameAssembly.dll at a VA with hex bytes.
    Patch { va: u64, hex: String },
    /// List entries of an XDF container (LuaScripts.xdf and siblings),
    /// optionally filtered by a case-insensitive substring.
    Xdf {
        container: std::path::PathBuf,
        filter: Option<String>,
        limit: usize,
    },
    /// Dump the printable constant strings of one LuaJIT bytecode entry
    /// inside an XDF container.
    XdfStrings {
        container: std::path::PathBuf,
        entry: String,
        limit: usize,
    },
    /// Write one XDF entry's raw bytes to stdout (extract .proto/.lua
    /// files verbatim).
    XdfCat {
        container: std::path::PathBuf,
        entry: String,
    },
    /// Open a framed control connection to a gate and request an encrypt
    /// token (the unauthenticated pre-login request every client performs).
    GateProbe { host: String, port: u16 },
}

impl Command {
    /// Build a `classes` command with the Python default limit.
    pub fn classes(pattern: impl Into<String>) -> Self {
        Self::Classes {
            pattern: pattern.into(),
            limit: limits::CLASSES,
        }
    }

    /// Build a `methods` command with the Python default limit.
    pub fn methods(pattern: impl Into<String>) -> Self {
        Self::Methods {
            pattern: pattern.into(),
            limit: limits::METHODS,
        }
    }

    /// Build a `fields` command with the Python default limit.
    pub fn fields(pattern: impl Into<String>) -> Self {
        Self::Fields {
            pattern: pattern.into(),
            limit: limits::FIELDS,
        }
    }

    /// Build an `addr` command with the Python default limit.
    pub fn addr(needle: impl Into<String>) -> Self {
        Self::Addr {
            needle: needle.into(),
            limit: limits::ADDRESSES,
        }
    }

    /// Build a `str` command with the Python default limit.
    pub fn str(pattern: impl Into<String>) -> Self {
        Self::Str {
            pattern: pattern.into(),
            limit: limits::STRINGS,
        }
    }
}

/// A rediscovered section entry from [`Command::Discover`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionEntry {
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

/// Structured result of one command.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Output {
    Dump(Box<DumpReport>),
    Sections(Vec<SectionEntry>),
    Classes(Vec<ClassMatch>),
    Methods(Vec<MethodMatch>),
    Fields(Vec<String>),
    Addresses(Vec<AddressMatch>),
    Strings(Vec<StringLiteralMatch>),
    VaToOffset(u64),
    OffsetToVa(u64),
    Patched {
        va: u64,
        file_offset: u64,
        byte_count: usize,
    },
    /// Entries of an XDF container (name, sizes), filtered as requested.
    XdfEntries(Vec<apiimo_network::XdfEntry>),
    /// Result of probing one gate for an encrypt token.
    GateProbeResult {
        host: String,
        port: u16,
        token: Option<i64>,
        gate_info: Option<String>,
        other: Vec<(u16, usize)>,
    },
    /// Raw bytes of one XDF entry.
    XdfBytes(Vec<u8>),
    /// Printable constant strings of one LuaJIT entry, with the chunk's
    /// provenance header line first.
    LuaStrings {
        chunk_name: Option<String>,
        version: u8,
        strings: Vec<String>,
    },
}

impl Output {
    /// Serialize the result as pretty JSON for machine consumers such as
    /// AniiStudio.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("outputs are serializable")
    }
}

/// Entry point holding the resolved game root and optional overrides.
#[derive(Debug, Clone)]
pub struct Apiimo {
    game_dir: PathBuf,
    output_dir: Option<PathBuf>,
    /// Explicit dumper override; `None` selects the embedded-then-PATH chain.
    dumper_command: Option<PathBuf>,
    types_count: u32,
}

impl Apiimo {
    /// Locate the game root the way the Python tool does: `APIIMO_GAME`
    /// environment variable, then an upward walk from the working directory.
    pub fn discover() -> Self {
        Self {
            game_dir: default_game_dir(),
            output_dir: None,
            dumper_command: None,
            types_count: TYPES_IN_BINARY,
        }
    }

    /// Bind the toolkit to an explicit game root.
    pub fn with_game_dir(game_dir: impl Into<PathBuf>) -> Self {
        Self {
            game_dir: game_dir.into(),
            output_dir: None,
            dumper_command: None,
            types_count: TYPES_IN_BINARY,
        }
    }

    pub fn game_dir(&self) -> &std::path::Path {
        &self.game_dir
    }

    /// Redirect dump/query outputs to a specific directory instead of
    /// `<game>/.dump`.
    pub fn set_output_dir(&mut self, dir: impl Into<PathBuf>) -> &mut Self {
        self.output_dir = Some(dir.into());
        self
    }

    /// Use a specific Il2CppDumper executable (or `.dll`, run via dotnet) for
    /// the dump pipeline, bypassing the embedded/PATH chain.
    pub fn set_dumper_command(&mut self, command: impl Into<PathBuf>) -> &mut Self {
        self.dumper_command = Some(command.into());
        self
    }

    /// Override the MetadataRegistration type count used when sanitizing
    /// default values (relevant when a game update changes the binary).
    pub fn set_types_count(&mut self, count: u32) -> &mut Self {
        self.types_count = count;
        self
    }

    /// Execute one command against the configured game root.
    pub fn run(&self, command: &Command) -> Result<Output, ApiError> {
        match command {
            Command::Dump => self.run_dump_with_fallback(),
            Command::Discover => {
                let metadata_file = apiimo_core::metadata_path(&self.game_dir);
                let raw = std::fs::read(&metadata_file).map_err(|source| ApiError::Io {
                    path: metadata_file,
                    source,
                })?;
                let layout = apiimo_core::discover_sections(&raw)?;
                let sections = layout
                    .iter()
                    .map(|(name, section)| SectionEntry {
                        name: name.to_string(),
                        offset: section.offset as u64,
                        size: section.size as u64,
                    })
                    .collect();
                Ok(Output::Sections(sections))
            }
            Command::Classes { pattern, limit } => Ok(Output::Classes(find_classes(
                self.dump_cs()?,
                pattern,
                *limit,
            )?)),
            Command::Methods { pattern, limit } => Ok(Output::Methods(find_methods(
                self.dump_cs()?,
                pattern,
                *limit,
            )?)),
            Command::Fields { pattern, limit } => Ok(Output::Fields(find_fields(
                self.dump_cs()?,
                pattern,
                *limit,
            )?)),
            Command::Addr { needle, limit } => Ok(Output::Addresses(find_addresses(
                &self.load_script()?,
                needle,
                *limit,
            )?)),
            Command::Str { pattern, limit } => Ok(Output::Strings(find_strings(
                &self.load_script()?,
                pattern,
                *limit,
            )?)),
            Command::Va2Off { va } => {
                let image = self.pe_image()?;
                let offset = image.va_to_file_offset(*va).ok_or_else(|| {
                    ApiError::Core(apiimo_core::Error::InvalidPe(format!(
                        "VA {va:#x} is not mapped"
                    )))
                })?;
                Ok(Output::VaToOffset(offset as u64))
            }
            Command::Off2Va { offset } => {
                let image = self.pe_image()?;
                let va = image.file_offset_to_va(*offset as usize).ok_or_else(|| {
                    ApiError::Core(apiimo_core::Error::InvalidPe(format!(
                        "file offset {offset:#x} is not mapped"
                    )))
                })?;
                Ok(Output::OffsetToVa(va))
            }
            Command::Patch { va, hex } => {
                let mut image = self.pe_image()?;
                let byte_count = hex
                    .bytes()
                    .filter(|byte| !byte.is_ascii_whitespace())
                    .count()
                    / 2;
                let file_offset = image.patch_hex(*va, hex)? as u64;
                Ok(Output::Patched {
                    va: *va,
                    file_offset,
                    byte_count,
                })
            }
            Command::Xdf {
                container,
                filter,
                limit,
            } => {
                let mut xdf = apiimo_network::XdfContainer::open(container)?;
                let entries = match filter {
                    Some(needle) => xdf.find(needle)?,
                    None => xdf.entries()?,
                };
                Ok(Output::XdfEntries(
                    entries.into_iter().take(*limit).collect(),
                ))
            }
            Command::XdfStrings {
                container,
                entry,
                limit,
            } => {
                let mut xdf = apiimo_network::XdfContainer::open(container)?;
                let chunk = xdf.read_lua_chunk(entry)?;
                Ok(Output::LuaStrings {
                    chunk_name: chunk.chunk_name,
                    version: chunk.version,
                    strings: chunk.strings.into_iter().take(*limit).collect(),
                })
            }
            Command::XdfCat { container, entry } => {
                let mut xdf = apiimo_network::XdfContainer::open(container)?;
                Ok(Output::XdfBytes(xdf.read(entry)?))
            }
            Command::GateProbe { host, port } => {
                let mut conn = apiimo_network::GateConnection::connect(
                    host,
                    *port,
                    std::time::Duration::from_secs(8),
                )
                .map_err(|error| apiimo_network::NetworkError::Xdf(error.to_string()))?;
                let result = conn
                    .probe(8)
                    .map_err(|error| apiimo_network::NetworkError::Xdf(error.to_string()))?;
                Ok(Output::GateProbeResult {
                    host: host.clone(),
                    port: *port,
                    token: result.encrypt_token.as_ref().map(|t| t.token),
                    gate_info: result.gate_info.as_ref().map(|g| format!("{g:?}")),
                    other: result
                        .other_frames
                        .iter()
                        .map(|f| (f.method, f.body.len()))
                        .collect(),
                })
            }
        }
    }

    /// Run the dump pipeline through the dumper candidate chain.
    ///
    /// An explicit `--dumper`/`set_dumper_command` path is used as-is. With
    /// no explicit choice, the embedded dumper (extracted on demand) is
    /// preferred, falling back to `il2cpp-dumper` on PATH when extraction
    /// or execution fails. Pipeline errors unrelated to the dumper (bad
    /// metadata, missing files) abort immediately.
    fn run_dump_with_fallback(&self) -> Result<Output, ApiError> {
        let candidates: Vec<PathBuf> = match &self.dumper_command {
            Some(explicit) => vec![explicit.clone()],
            None => {
                let mut candidates = Vec::new();
                match dumper::ensure_extracted() {
                    Ok(embedded) => candidates.extend(embedded),
                    // Extraction failed; the PATH dumper may still work.
                    Err(error) => eprintln!("apiimo: embedded dumper unusable ({error})"),
                }
                candidates.push(PathBuf::from("il2cpp-dumper"));
                candidates
            }
        };

        let mut last_report = None;
        let mut last_error = None;
        for dumper in &candidates {
            let mut options = DumpOptions::new(&self.game_dir);
            options.output_dir = self.output_dir.clone();
            options.dumper_command = dumper.clone().into();
            options.types_count = self.types_count;
            match run_dump(&options) {
                Ok(report) if report.dumper_succeeded => {
                    return Ok(Output::Dump(Box::new(report)));
                }
                // The dumper ran but exited nonzero: remember it and let the
                // next candidate try (the final report is still returned).
                Ok(report) => last_report = Some(Output::Dump(Box::new(report))),
                // Only dumper-launch failures justify retrying with the next
                // candidate; everything else is deterministic.
                Err(error @ apiimo_core::Error::DumperStart(_)) => {
                    last_error = Some(ApiError::Core(error));
                }
                Err(error) => return Err(ApiError::Core(error)),
            }
        }
        if let Some(report) = last_report {
            return Ok(report);
        }
        Err(
            last_error.unwrap_or(ApiError::Core(apiimo_core::Error::DumperStart(
                "no dumper candidate could be executed".into(),
            ))),
        )
    }

    fn dump_cs(&self) -> Result<PathBuf, ApiError> {
        let dir = output_path(&self.game_dir, self.output_dir.as_deref())?;
        let path = dir.join("dump.cs");
        if !path.exists() {
            return Err(ApiError::MissingDump { path });
        }
        Ok(path)
    }

    fn load_script(&self) -> Result<serde_json::Value, ApiError> {
        let dir = output_path(&self.game_dir, self.output_dir.as_deref())?;
        Ok(load_script(&dir)?)
    }

    fn pe_image(&self) -> Result<PeImage, ApiError> {
        Ok(PeImage::from_file(apiimo_core::binary_path(
            &self.game_dir,
        ))?)
    }
}

impl Default for Apiimo {
    fn default() -> Self {
        Self::discover()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructors_apply_python_defaults() {
        assert_eq!(
            Command::classes("Player"),
            Command::Classes {
                pattern: "Player".into(),
                limit: 100
            }
        );
        assert_eq!(
            Command::addr("GetSwitchConfig"),
            Command::Addr {
                needle: "GetSwitchConfig".into(),
                limit: 20
            }
        );
    }

    #[test]
    fn outputs_serialize_for_ans_apiimo() {
        let output = Output::Classes(vec![ClassMatch {
            namespace: "NTESHTPSec".into(),
            name: "AntiCheatResult".into(),
            type_index: Some(27781),
        }]);
        let json = output.to_json();
        assert!(json.contains("AntiCheatResult"));
        assert!(json.contains("27781"));
    }
}
