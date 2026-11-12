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

use std::io::Read as _;
use std::path::{Path, PathBuf};

use apiimo_core::{
    default_game_dir, find_addresses, find_classes, find_fields, find_methods, find_strings,
    load_script, output_path, run_dump, AddressMatch, ClassMatch, DumpOptions, DumpReport,
    MethodMatch, PeImage, StringLiteralMatch,
};
use serde::{Deserialize, Serialize};

/// Lowercase hex encoding for raw byte output.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a hex string into bytes.
pub(crate) fn decode_hex(s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        // pad a leading nibble so "abc" still parses deterministically
        return decode_hex(&format!("0{s}"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

/// Keep the decoded inspection copy separate from the byte-preserved download.
/// Older Apiimo builds used `.bin` for both paths and silently replaced the
/// original compressed capture when the caller accepted the CLI default.
fn decoded_save_path(raw_path: &Path) -> PathBuf {
    if raw_path.extension().and_then(|value| value.to_str()) == Some("bin") {
        raw_path.with_extension("decoded.bin")
    } else {
        raw_path.with_extension("bin")
    }
}

/// Undo the gate's per-frame body compression, returning the bytes and the
/// codec that matched ("zlib", "deflate", "zstd", or "raw" when the body is
/// already plain protobuf).
pub(crate) fn decompress_body(body: &[u8]) -> (Vec<u8>, &'static str) {
    if body.is_empty() {
        return (Vec::new(), "raw");
    }
    if let Some(out) = try_decompress(flate2::read::ZlibDecoder::new(body)) {
        return (out, "zlib");
    }
    if let Some(out) = try_decompress(flate2::read::DeflateDecoder::new(body)) {
        return (out, "deflate");
    }
    if let Ok(mut decoder) = ruzstd::StreamingDecoder::new(body) {
        let mut out = Vec::new();
        if decoder.read_to_end(&mut out).is_ok() && !out.is_empty() {
            return (out, "zstd");
        }
    }
    (body.to_vec(), "raw")
}

/// Read a flate2 decoder to the end, accepting only full, non-empty streams.
fn try_decompress<D: std::io::Read>(decoder: D) -> Option<Vec<u8>> {
    let mut decoder = decoder;
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// One gate's liveness, as reported by `gate-status`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GateStatusRow {
    pub host: String,
    pub port: u16,
    pub purpose: String,
    pub status: String,
    pub token: Option<i64>,
    pub detail: String,
}

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
    /// Print the metadata keystream only: the banked key when one matches
    /// the build, statistical recovery otherwise. `metadata` defaults to
    /// the game root's global-metadata.dat; `out` optionally writes the
    /// hex to a file; `--recover` skips the banked lookup on purpose.
    Key {
        metadata: Option<PathBuf>,
        out: Option<PathBuf>,
        force_recover: bool,
    },
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
    /// Full anonymous key exchange: token + our RSA-wrapped session key.
    /// Saves the key material for offline cipher analysis.
    GateHandshake { host: String, port: u16 },
    /// Download this account's client-info save blob from the object
    /// storage bucket (world-readable; no login involved).
    SavePull { uid: String, out: PathBuf },
    /// RC4-decrypt a captured gate stream with a session key (hex) and
    /// report the gate frames found inside.
    GateDecrypt {
        key_hex: String,
        input: PathBuf,
        output: PathBuf,
        /// Offset of the first encrypted byte; preceding bytes are not guessed or decoded.
        encrypted_offset: usize,
    },
    /// Become the client: full handshake + LoginService.verifySdk with the
    /// banked FPX credentials, printing the login response.
    GateLogin {
        msgate: String,
        credentials: PathBuf,
    },
    /// The full login chain against a FRESH ticket: verifySdk -> CS_Login
    /// -> PhonestGate.bind, then the WORLD gate: connectServer{auth} and
    /// capture of the save stream to `out`.
    WorldPull {
        msgate: String,
        worldgate: String,
        credentials: PathBuf,
        uid: u64,
        out: PathBuf,
    },
    /// Probe every known production game gate and classify each as up,
    /// forbidden (maintenance), or unreachable.
    GateStatus,
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
    GateLogin(apiimo_api_shim::GateLoginData),
    WorldPull(Box<apiimo_api_shim::WorldPullData>),
    Dump(Box<DumpReport>),
    /// The keystream of a metadata file: which banked build key matched, or
    /// that statistical recovery produced it. `key_hex` is empty when the
    /// file is not encrypted. Without `out`, rendering prints the hex alone
    /// so stdout can be redirected straight into a key file.
    KeyResult {
        source: String,
        key_hex: String,
        out: Option<PathBuf>,
    },
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
    /// Anonymous handshake outcome (token + raw post-confirm server bytes).
    GateHandshakeResult {
        host: String,
        token: i64,
        key_hex: String,
        frames: Vec<String>,
    },
    /// Result of probing one gate for an encrypt token.
    GateProbeResult {
        host: String,
        port: u16,
        token: Option<i64>,
        gate_info: Option<String>,
        other: Vec<(u16, usize)>,
    },
    /// Client-info save blob pulled from object storage.
    SavePullResult {
        uid: String,
        url: String,
        path: PathBuf,
        raw_bytes: usize,
        decoded_bytes: usize,
        format: String,
    },
    /// RC4-decoded gate stream and the frames recovered from it.
    GateDecryptResult {
        key_bytes: usize,
        input_bytes: usize,
        output_path: PathBuf,
        frames: Vec<String>,
    },
    /// Liveness of every known production game gate.
    GateStatusTable {
        entries: Vec<GateStatusRow>,
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
}

impl Apiimo {
    /// Locate the game root the way the Python tool does: `APIIMO_GAME`
    /// environment variable, then an upward walk from the working directory.
    pub fn discover() -> Self {
        Self {
            game_dir: default_game_dir(),
            output_dir: None,
            dumper_command: None,
        }
    }

    /// Bind the toolkit to an explicit game root.
    pub fn with_game_dir(game_dir: impl Into<PathBuf>) -> Self {
        Self {
            game_dir: game_dir.into(),
            output_dir: None,
            dumper_command: None,
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
    /// Execute one command against the configured game root.
    pub fn run(&self, command: &Command) -> Result<Output, ApiError> {
        match command {
            Command::Dump => self.run_dump_with_fallback(),
            Command::Key {
                metadata,
                out,
                force_recover,
            } => {
                let path = metadata
                    .clone()
                    .unwrap_or_else(|| apiimo_core::metadata_path(&self.game_dir));
                let raw = std::fs::read(&path).map_err(|source| ApiError::Io {
                    path: path.clone(),
                    source,
                })?;
                if raw.len() < apiimo_crypto::HEADER_SIZE {
                    return Err(ApiError::Core(apiimo_core::Error::InvalidMetadata(
                        format!(
                            "metadata is shorter than the {}-byte header",
                            apiimo_crypto::HEADER_SIZE
                        ),
                    )));
                }
                let version =
                    u32::from_le_bytes(raw[4..8].try_into().expect("length checked above"));
                if version == apiimo_crypto::VERSION {
                    return Ok(Output::KeyResult {
                        source: "not encrypted - the file already carries a vanilla header".into(),
                        key_hex: String::new(),
                        out: out.clone(),
                    });
                }
                let recovered = |raw: &[u8]| {
                    apiimo_crypto::recover_key_refined(raw)
                        .map_err(|error| ApiError::Core(error.into()))
                };
                let (key, source) = if *force_recover {
                    eprintln!(
                        "apiimo: --recover set; running statistical recovery \
                         (about a minute on a 28 MB build)..."
                    );
                    (
                        recovered(&raw)?,
                        "statistical recovery (--recover forced)".to_string(),
                    )
                } else {
                    match apiimo_crypto::select_embedded_key(&raw) {
                        Some(banked) => {
                            let tag = apiimo_crypto::embedded_key_tag(banked)
                                .unwrap_or_else(|| "unknown build".into());
                            (banked.to_vec(), format!("embedded key matched: {tag}"))
                        }
                        None => {
                            eprintln!(
                                "apiimo: no embedded key matches; running statistical \
                                 recovery (about a minute on a 28 MB build)..."
                            );
                            (
                                recovered(&raw)?,
                                "statistical recovery (new build)".to_string(),
                            )
                        }
                    }
                };
                let key_hex = hex(&key);
                if let Some(out) = out {
                    std::fs::write(out, format!("{key_hex}\n")).map_err(|source| ApiError::Io {
                        path: out.clone(),
                        source,
                    })?;
                } else {
                    eprintln!("apiimo: {source} ({} bytes)", key.len());
                }
                Ok(Output::KeyResult {
                    source,
                    key_hex,
                    out: out.clone(),
                })
            }
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
            Command::GateHandshake { host, port } => {
                let key_der =
                    std::fs::read(self.gate_key_path()).map_err(|source| ApiError::Io {
                        path: self.gate_key_path(),
                        source,
                    })?;
                let mut conn = apiimo_network::GateConnection::connect(
                    host,
                    *port,
                    std::time::Duration::from_secs(8),
                )
                .map_err(|error| apiimo_network::NetworkError::Xdf(error.to_string()))?;
                let (outcome, material) = conn
                    .anonymous_handshake(&key_der)
                    .map_err(|error| apiimo_network::NetworkError::Xdf(error.to_string()))?;
                Ok(Output::GateHandshakeResult {
                    host: host.clone(),
                    token: outcome.token,
                    key_hex: hex(&material.key),
                    frames: outcome
                        .post_confirm_frames
                        .into_iter()
                        .map(|(ours, bytes)| {
                            format!("{} {}", if ours { "C" } else { "S" }, hex(&bytes))
                        })
                        .collect(),
                })
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
            Command::SavePull { uid, out } => {
                let url = format!(
                    "https://worldx-global-assets.oss-us-east-1.aliyuncs.com/\
                     us/prod/ClientInfo/{uid}_client_info_bin"
                );
                let response = ureq::get(&url).call().map_err(|error| {
                    apiimo_network::NetworkError::Xdf(format!("save pull failed: {error}"))
                })?;
                let mut raw = Vec::new();
                response
                    .into_reader()
                    .read_to_end(&mut raw)
                    .map_err(|error| {
                        apiimo_network::NetworkError::Xdf(format!("save read failed: {error}"))
                    })?;
                let raw_len = raw.len();
                std::fs::write(out, &raw).map_err(|source| ApiError::Io {
                    path: out.clone(),
                    source,
                })?;
                // The blob is zstd-compressed; decode for immediate inspection.
                let (decoded, format) = match ruzstd::StreamingDecoder::new(&raw[..]) {
                    Ok(mut decoder) => {
                        use std::io::Read;
                        let mut plain = Vec::new();
                        decoder
                            .read_to_end(&mut plain)
                            .map_err(|error| {
                                apiimo_network::NetworkError::Xdf(format!(
                                    "zstd decode failed: {error}"
                                ))
                            })?;
                        let decoded_path = decoded_save_path(out);
                        debug_assert_ne!(decoded_path.as_path(), out.as_path());
                        std::fs::write(&decoded_path, &plain).map_err(|source| ApiError::Io {
                            path: decoded_path.clone(),
                            source,
                        })?;
                        (plain.len(), format!("zstd -> {}", decoded_path.display()))
                    }
                    Err(_) => (raw_len, "raw (not zstd)".to_string()),
                };
                Ok(Output::SavePullResult {
                    uid: uid.clone(),
                    url,
                    path: out.clone(),
                    raw_bytes: raw_len,
                    decoded_bytes: decoded,
                    format,
                })
            }
            Command::GateDecrypt {
                key_hex,
                input,
                output,
                encrypted_offset,
            } => {
                let key = decode_hex(key_hex).map_err(|error| {
                    apiimo_network::NetworkError::Xdf(format!("bad key hex: {error:?}"))
                })?;
                let data = std::fs::read(input).map_err(|source| ApiError::Io {
                    path: input.clone(),
                    source,
                })?;
                let input_len = data.len();
                let encrypted = data.get(*encrypted_offset..).ok_or_else(||
                    apiimo_network::NetworkError::Xdf("encrypted offset exceeds input length".into()))?;
                let mut decoder = apiimo_network::StreamDecoder::new(&key)
                    .map_err(|e| apiimo_network::NetworkError::Xdf(e.into()))?;
                let mut decoded = Vec::new();
                for chunk in encrypted.chunks(65536) {
                    decoded.extend(decoder.feed(chunk).map_err(|e| apiimo_network::NetworkError::Xdf(e.into()))?);
                }
                if decoded.is_empty() || decoder.pending_frame_bytes() != 0 || decoder.pending_compressed_bytes() != 0 {
                    return Err(apiimo_network::NetworkError::Xdf("capture has no complete frames or ends with partial data".into()).into());
                }
                let mut out_bytes = Vec::new();
                let mut frame_codecs = Vec::new();
                for (method, body) in &decoded {
                    out_bytes.extend_from_slice(&((body.len() + 2) as u32).to_le_bytes());
                    out_bytes.extend_from_slice(&method.to_le_bytes());
                    out_bytes.extend_from_slice(body);
                    frame_codecs.push(format!("m{method} {}B continuous RC4/zlib", body.len()));
                }
                std::fs::write(output, &out_bytes).map_err(|source| ApiError::Io {
                    path: output.clone(),
                    source,
                })?;
                let frames = frame_codecs;
                Ok(Output::GateDecryptResult {
                    key_bytes: key.len(),
                    input_bytes: input_len,
                    output_path: output.clone(),
                    frames,
                })
            }
            Command::GateLogin {
                msgate,
                credentials,
            } => gate_login(msgate.to_string(), credentials.clone()).map(Output::GateLogin),
            Command::WorldPull {
                msgate,
                worldgate,
                credentials,
                uid,
                out,
            } => world_pull(
                msgate.to_string(),
                worldgate.to_string(),
                credentials.clone(),
                *uid,
                out.clone(),
            )
            .map(|data| Output::WorldPull(Box::new(data))),
            Command::GateStatus => {
                use apiimo_network::{EndpointClass, GateStatus as GateState};
                let mut entries = Vec::new();
                for endpoint in apiimo_network::ENDPOINTS.iter() {
                    if endpoint.class != EndpointClass::GameGate
                        || endpoint.environment != apiimo_network::EndpointEnvironment::Production
                    {
                        continue;
                    }
                    let port = endpoint.port.unwrap_or(10000);
                    let host = endpoint.host;
                    let (status, token, detail) = match apiimo_network::GateConnection::connect(
                        host,
                        port,
                        std::time::Duration::from_secs(4),
                    ) {
                        Ok(mut conn) => match conn.probe(4) {
                            Ok(result) => {
                                let status = match result.status() {
                                    GateState::Up => "UP",
                                    GateState::Forbidden => "FORBIDDEN (maintenance)",
                                    GateState::NoResponse => "NO RESPONSE",
                                };
                                let detail = result
                                    .gate_info
                                    .as_ref()
                                    .map(|info| {
                                        let f1 = info
                                            .bytes(1)
                                            .map(|b| String::from_utf8_lossy(b).into_owned())
                                            .unwrap_or_default();
                                        let f2 = info
                                            .bytes(2)
                                            .map(|b| String::from_utf8_lossy(b).into_owned())
                                            .unwrap_or_default();
                                        format!("gate-info: {f1:?} / {f2:?}")
                                    })
                                    .unwrap_or_default();
                                (
                                    status,
                                    result.encrypt_token.as_ref().map(|t| t.token),
                                    detail,
                                )
                            }
                            Err(error) => ("PROBE ERROR", None, format!("{error}")),
                        },
                        Err(error) => ("UNREACHABLE", None, format!("{error}")),
                    };
                    entries.push(GateStatusRow {
                        host: host.to_string(),
                        port,
                        purpose: endpoint.purpose.to_string(),
                        status: status.to_string(),
                        token,
                        detail,
                    });
                }
                Ok(Output::GateStatusTable { entries })
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

    /// Path of the extracted gate RSA public key (PKCS#1 DER).
    fn gate_key_path(&self) -> PathBuf {
        std::env::var("APIIMO_GATE_KEY")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("../.captures/gate_rsa/gate_rsa_2048.der"))
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
    fn key_command_reports_the_matching_banked_keystream() {
        // A synthetic encrypted build: printable plaintext large enough to
        // cover the selector window, XORed with the first banked keystream.
        // The command must select that build and echo its key exactly.
        let banked_key = apiimo_crypto::build_keys()[0].key.clone();
        let plaintext: Vec<u8> = b"Aniimo key-command test plaintext. "
            .iter()
            .copied()
            .cycle()
            .take(0x70000)
            .collect();
        let ciphertext =
            apiimo_crypto::xor_repeating(&plaintext, &banked_key, 0).expect("xor is total");
        let path = std::env::temp_dir().join(format!("apiimo-key-test-{}.dat", std::process::id()));
        std::fs::write(&path, &ciphertext).expect("write temp ciphertext");
        let output = Apiimo::discover()
            .run(&Command::Key {
                metadata: Some(path.clone()),
                out: None,
                force_recover: false,
            })
            .unwrap();
        let _ = std::fs::remove_file(&path);
        let Output::KeyResult {
            source,
            key_hex,
            out,
        } = output
        else {
            panic!("expected KeyResult, got {output:?}");
        };
        assert!(out.is_none());
        assert!(source.contains("embedded key matched"), "{source}");
        assert_eq!(key_hex, hex(&banked_key));
    }

    #[test]
    #[ignore = "point APIIMO_TEST_METADATA at a real encrypted global-metadata.dat"]
    fn key_command_matches_banked_key_on_real_metadata() {
        let Ok(path) = std::env::var("APIIMO_TEST_METADATA") else {
            return;
        };
        let output = Apiimo::discover()
            .run(&Command::Key {
                metadata: Some(path.into()),
                out: None,
                force_recover: false,
            })
            .unwrap();
        let Output::KeyResult {
            source, key_hex, ..
        } = output
        else {
            panic!("expected KeyResult, got {output:?}");
        };
        assert!(source.contains("embedded key matched"), "{source}");
        assert!(apiimo_crypto::build_keys()
            .iter()
            .any(|build| hex(&build.key) == key_hex));
    }

    #[test]
    fn decompress_body_detects_zlib_and_falls_through() {
        use std::io::Write as _;
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"hello save body").unwrap();
        let zlib_frame = encoder.finish().unwrap();
        let (out, codec) = decompress_body(&zlib_frame);
        assert_eq!(codec, "zlib");
        assert_eq!(out, b"hello save body");
        // Plain protobuf-looking bytes pass through untouched.
        let raw = [0x08u8, 0x01, 0x12, 0x03, b'a', b'b', b'c'];
        let (out, codec) = decompress_body(&raw);
        assert_eq!(codec, "raw");
        assert_eq!(out, raw.to_vec());
    }

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

    #[test]
    fn decoded_save_path_never_overwrites_raw_capture() {
        assert_eq!(
            decoded_save_path(Path::new("client_info_123.zst")),
            PathBuf::from("client_info_123.bin")
        );
        assert_eq!(
            decoded_save_path(Path::new("client_info_123.bin")),
            PathBuf::from("client_info_123.decoded.bin")
        );
    }
}

// ---------------------------------------------------------------------------
// gate-login: become the client
// ---------------------------------------------------------------------------

/// Read + parse a credentials json (ticket, account_id, channel_uid, ...).
fn read_credentials(path: &PathBuf) -> Result<serde_json::Value, ApiError> {
    let raw = std::fs::read_to_string(path).map_err(|source| ApiError::Io {
        path: path.clone(),
        source,
    })?;
    serde_json::from_str(&raw).map_err(|e| ApiError::Io {
        path: path.clone(),
        source: std::io::Error::other(e.to_string()),
    })
}

/// The gate RSA public key ships inside the game's Lua container
/// (conf.json pubKeyData) - load and convert to PKCS#1 DER.
fn load_gate_pubkey_der() -> Result<Vec<u8>, ApiError> {
    use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
    let game = default_game_dir();
    let xdf_path = game.join("Aniimo_Data/StreamingAssets/cvs/res/lua/LuaScripts.xdf");
    let mut xdf = apiimo_network::XdfContainer::open(&xdf_path).map_err(|e| ApiError::Io {
        path: xdf_path.clone(),
        source: std::io::Error::other(e.to_string()),
    })?;
    let conf = xdf
        .read("xfs/luascripts/Network/conf.json")
        .map_err(|e| ApiError::Io {
            path: xdf_path,
            source: std::io::Error::other(e.to_string()),
        })?;
    let conf_json: serde_json::Value = serde_json::from_slice(&conf).map_err(|e| ApiError::Io {
        path: PathBuf::from("conf.json"),
        source: std::io::Error::other(e.to_string()),
    })?;
    let pem = conf_json["pubKeyData"]
        .as_str()
        .ok_or_else(|| ApiError::Io {
            path: PathBuf::from("conf.json"),
            source: std::io::Error::other("conf.json missing pubKeyData"),
        })?;
    let public_key = rsa::RsaPublicKey::from_pkcs1_pem(pem).map_err(|e| ApiError::Io {
        path: PathBuf::from("conf.json"),
        source: std::io::Error::other(format!("bad PEM: {e}")),
    })?;
    let der = public_key.to_pkcs1_der().map_err(|e| ApiError::Io {
        path: PathBuf::from("conf.json"),
        source: std::io::Error::other(e.to_string()),
    })?;
    Ok(der.as_bytes().to_vec())
}

fn split_host_port(target: &str, default_port: u16) -> (String, u16) {
    match target.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
        None => (target.to_string(), default_port),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Run the full ms-gate login: handshake with OUR key, connectServer,
/// then LoginService.verifySdk with the banked FPX ticket.
fn gate_login(
    msgate: String,
    credentials: PathBuf,
) -> Result<apiimo_api_shim::GateLoginData, ApiError> {
    use apiimo_network::LiveSession;

    let creds = read_credentials(&credentials)?;
    let ticket = creds["ticket"]
        .as_str()
        .ok_or_else(|| ApiError::Io {
            path: credentials.clone(),
            source: std::io::Error::other("credentials missing 'ticket'"),
        })?
        .to_string();
    let der = load_gate_pubkey_der()?;
    let (host, port) = split_host_port(&msgate, 10000);

    eprintln!("[gate-login] establishing session...");
    let mut session = LiveSession::establish(&host, port, &der).map_err(|e| ApiError::Io {
        path: PathBuf::from(format!("{host}:{port}")),
        source: std::io::Error::other(e.to_string()),
    })?;
    eprintln!("[gate-login] established; the ms-gate never gets connectServer (that is world-gate only - the login gates answer it Busy by design)");
    let key_hex = hex_encode(&session.key);

    // verifySdk with the banked ticket - byte-exact message shape
    eprintln!("[gate-login] calling verifySdk...");
    let resp = session.verify_sdk(&ticket).map_err(|e| ApiError::Io {
        path: PathBuf::from("verifySdk"),
        source: std::io::Error::other(e.to_string()),
    })?;

    let response_utf8 = String::from_utf8_lossy(&resp).to_string();
    Ok(apiimo_api_shim::GateLoginData {
        msgate: format!("{host}:{port}"),
        token: 0,
        session_key_hex: key_hex,
        response_hex: resp.iter().map(|b| format!("{b:02x}")).collect(),
        response_utf8,
    })
}

// ---------------------------------------------------------------------------
// world-pull: verifySdk -> CS_Login -> bind -> world gate -> save stream
// ---------------------------------------------------------------------------

/// Execute the full login chain with a FRESH ticket, then open the world
/// gate with connectServer{auth} and capture the save stream frames.
///
/// Credentials json fields: `ticket` (required), optional overrides
/// `account_id`, `client_version`, `client_config_version`,
/// `session_id_hex` / `gate_id_hex` (24 hex chars each), `sdk_info_json`.
/// Everything optional falls back to the capture-decoded 2026-09-25 values
/// or a runtime-synthesized substitute.
fn world_pull(
    msgate: String,
    worldgate: String,
    credentials: PathBuf,
    uid: u64,
    out: PathBuf,
) -> Result<apiimo_api_shim::WorldPullData, ApiError> {
    use apiimo_network::login_chain;
    use apiimo_network::LiveSession;

    let mut notes = Vec::new();
    let creds = read_credentials(&credentials)?;
    let ticket = creds["ticket"]
        .as_str()
        .ok_or_else(|| ApiError::Io {
            path: credentials.clone(),
            source: std::io::Error::other(
                "credentials missing 'ticket' (run \
                keyhound/fresh_ticket_run.py after a game boot)",
            ),
        })?
        .to_string();
    let account_id = creds["account_id"]
        .as_str()
        .unwrap_or("fp_account_global:2044122406")
        .to_string();

    let der = load_gate_pubkey_der()?;
    let (ms_host, ms_port) = split_host_port(&msgate, 10000);

    // --- 1. ms-gate: handshake + verifySdk ---
    eprintln!("[world-pull] ms-gate session...");
    let mut ms = LiveSession::establish(&ms_host, ms_port, &der).map_err(|e| ApiError::Io {
        path: PathBuf::from(format!("{ms_host}:{ms_port}")),
        source: std::io::Error::other(e.to_string()),
    })?;
    let msgate_key_hex = hex_encode(&ms.key);
    eprintln!("[world-pull] verifySdk with fresh ticket...");
    let verify_resp = ms.verify_sdk(&ticket).map_err(|e| ApiError::Io {
        path: PathBuf::from("verifySdk"),
        source: std::io::Error::other(e.to_string()),
    })?;
    let verify_bytes = verify_resp.len();

    // --- 2. extract the login-auth blob the response issues ---
    let auth = match login_chain::extract_login_auth(&verify_resp) {
        Some(a) => a,
        None => {
            notes.push(format!(
                "verifySdk response ({verify_bytes}B) carried no recognizable \
                 {{Username,Expired,Sign}} blob; raw: {}",
                hex_encode(&verify_resp)
            ));
            return Ok(apiimo_api_shim::WorldPullData {
                msgate: format!("{ms_host}:{ms_port}"),
                worldgate: worldgate.clone(),
                account_id,
                uid,
                verify_bytes,
                cs_login_bytes: 0,
                bind_bytes: 0,
                connect_resp: None,
                frames_captured: 0,
                out: out.display().to_string(),
                msgate_key_hex,
                world_key_hex: String::new(),
                notes,
            });
        }
    };
    notes.push(format!(
        "login-auth: Username={} Expired={} Sign={}...",
        auth.username,
        auth.expired,
        &auth.sign[..12.min(auth.sign.len())]
    ));

    // --- 3. CS_Login + PhonestGate.bind ---
    let client_version = creds["client_version"]
        .as_str()
        .unwrap_or("2026092202")
        .to_string();
    let (client_config_version, ccv_placeholder) = match creds["client_config_version"].as_str() {
        Some(v) => (v.to_string(), false),
        None => ("278da592".to_string(), true),
    };
    if ccv_placeholder {
        notes.push(
            "clientConfigVersion falls back to the capture prefix - paste the \
             full value from a live capture into the credentials json"
                .to_string(),
        );
    }
    // 12B ObjectIds: credentials override, else the handshake m19 pushes,
    // else timestamp-synthesized.
    let (session_id, gate_id) = object_ids(&creds, &ms.pushes);
    let sdk_info_json = creds["sdk_info_json"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| {
            notes.push("sdkInfo json synthesized (banked 1875B blob not supplied)".into());
            format!(
                "{{\"log_source\":\"pc\",\"app_id\":\"worldx.global.prod\",\
                 \"channel_uid\":\"{}\",\"account_id\":\"{}\",\
                 \"properties\":{{\"sdk_version\":\"28.1.1\",\
                 \"channel_platform\":\"steam\",\"os_version\":\"Windows 10 64-bit\",\
                 \"device_model\":\"PC\",\"language\":\"en\"}}}}",
                creds["channel_uid"].as_str().unwrap_or("0"),
                account_id
            )
        });
    let cfg = login_chain::CsLoginConfig {
        client_version,
        client_config_version,
        server_id: creds["server_id"].as_u64().unwrap_or(100),
        scene_id: creds["DEFAULT_SCENE_ID"].as_u64().unwrap_or(3002),
        region_no: 0,
        session_id,
        gate_id,
        language: creds["language"].as_str().unwrap_or("en").to_string(),
        sdk_info_json,
    };

    eprintln!("[world-pull] CS_Login...");
    let cs_resp = ms
        .cs_login(&account_id, &auth.raw, uid, &cfg)
        .map_err(|e| ApiError::Io {
            path: PathBuf::from("CS_Login"),
            source: std::io::Error::other(e.to_string()),
        })?;
    let cs_login_bytes = cs_resp.len();
    eprintln!("[world-pull] PhonestGate.bind...");
    let bind_resp = ms.phonest_bind(uid).map_err(|e| ApiError::Io {
        path: PathBuf::from("PhonestGate.bind"),
        source: std::io::Error::other(e.to_string()),
    })?;
    let bind_bytes = bind_resp.len();

    // --- 4. world gate: connectServer{auth} + save stream capture ---
    let (wg_host, wg_port) = split_host_port(&worldgate, 20000);
    eprintln!("[world-pull] world gate session...");
    let mut world = LiveSession::establish(&wg_host, wg_port, &der).map_err(|e| ApiError::Io {
        path: PathBuf::from(format!("{wg_host}:{wg_port}")),
        source: std::io::Error::other(e.to_string()),
    })?;
    let world_key_hex = hex_encode(&world.key);
    let connect = login_chain::world_connect_server(&auth.raw, &cfg.client_version, &[]);
    world.connect_server(&connect).map_err(|e| ApiError::Io {
        path: PathBuf::from("connectServer"),
        source: std::io::Error::other(e.to_string()),
    })?;

    // capture the save stream: read until the deadline, keep every frame
    eprintln!("[world-pull] capturing save stream (12s)...");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
    let mut frames: Vec<(u16, Vec<u8>)> = Vec::new();
    while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
        match world.read_frames(left.min(std::time::Duration::from_millis(500))) {
            Ok(fs) => frames.extend(fs),
            Err(_) => break,
        }
    }
    let frames_captured = frames.len();
    login_chain::write_stream_dump(&out, &frames).map_err(|e| ApiError::Io {
        path: out.clone(),
        source: e,
    })?;
    let connect_resp = frames
        .iter()
        .find(|(m, _)| *m == 4)
        .and_then(|(_, b)| apiimo_network::ConnectServerResp::decode_pb(b).ok())
        .and_then(|r| r.resp_type);
    if let Some(t) = connect_resp {
        notes.push(format!(
            "connectResponse type={t} (1=connected, 0=busy, 2=refused)"
        ));
    }

    Ok(apiimo_api_shim::WorldPullData {
        msgate: format!("{ms_host}:{ms_port}"),
        worldgate: format!("{wg_host}:{wg_port}"),
        account_id,
        uid,
        verify_bytes,
        cs_login_bytes,
        bind_bytes,
        connect_resp,
        frames_captured,
        out: out.display().to_string(),
        msgate_key_hex,
        world_key_hex,
        notes,
    })
}

/// 12B ObjectIds for CS_Login: credentials override, then any 12-byte
/// bytes field the gate pushed during the handshake, else synthesized
/// (4B seconds + 5B random + 3B counter, ObjectId style).
fn object_ids(creds: &serde_json::Value, pushes: &[(u16, Vec<u8>)]) -> ([u8; 12], [u8; 12]) {
    let from_hex = |v: Option<&str>| -> Option<[u8; 12]> {
        let s = v?;
        if s.len() != 24 {
            return None;
        }
        let mut out = [0u8; 12];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(out)
    };
    let session = from_hex(creds["session_id_hex"].as_str());
    let gate = from_hex(creds["gate_id_hex"].as_str());
    if let (Some(s), Some(g)) = (session, gate) {
        return (s, g);
    }
    // scan handshake pushes for 12-byte protobuf bytes fields
    let mut found = Vec::new();
    for (_, body) in pushes {
        if let Ok(m) = apiimo_network::pb::decode(body) {
            for field in 1..16u32 {
                if let Some(b) = m.bytes(field) {
                    if b.len() == 12 {
                        found.push(b.to_vec());
                    }
                }
            }
        }
    }
    if found.len() >= 2 && session.is_none() && gate.is_none() {
        let mut s = [0u8; 12];
        let mut g = [0u8; 12];
        s.copy_from_slice(&found[0]);
        g.copy_from_slice(&found[1]);
        return (s, g);
    }
    // synthesize
    let synth = || {
        let mut v = [0u8; 12];
        v[..4].copy_from_slice(
            &(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32)
                .to_be_bytes(),
        );
        v
    };
    (session.unwrap_or_else(synth), gate.unwrap_or_else(synth))
}

/// Small holder so the report types stay out of the public enum noise.
pub mod apiimo_api_shim {
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct GateLoginData {
        pub msgate: String,
        pub token: i64,
        pub session_key_hex: String,
        pub response_hex: String,
        pub response_utf8: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct WorldPullData {
        pub msgate: String,
        pub worldgate: String,
        pub account_id: String,
        pub uid: u64,
        pub verify_bytes: usize,
        pub cs_login_bytes: usize,
        pub bind_bytes: usize,
        pub connect_resp: Option<i64>,
        pub frames_captured: usize,
        pub out: String,
        pub msgate_key_hex: String,
        pub world_key_hex: String,
        pub notes: Vec<String>,
    }
}
