//! Cryptographic primitives used by the Apiimo metadata pipeline.
//!
//! Each Aniimo build ships a repeating XOR keystream over the metadata body;
//! the keystreams recovered for known builds are embedded here and selected
//! automatically. For a fresh update whose keystream is not yet embedded,
//! [`recover_key_refined`] produces a new key from the ciphertext alone:
//! a statistical seed pass followed by a refinement guided by the string
//! byte distribution of known builds. These routines deliberately contain
//! no file-system or process logic; callers can use them with buffers,
//! test fixtures, or game files.

use std::fmt;
use std::sync::OnceLock;

/// The IL2CPP metadata sanity value.
pub const SANITY: u32 = 0xFAB1_1BAF;
/// The metadata version supported by the port.
pub const VERSION: u32 = 31;
/// Period of the recovered Aniimo keystream in bytes.
pub const KEY_PERIOD: usize = 1152;
/// Number of unencrypted header bytes at the beginning of the file.
pub const HEADER_SIZE: usize = 256;

/// Byte histogram over the string sections (stringLiteralData plus string
/// heaps) of both known builds, 14,131,366 bytes total. Smoothing happens at
/// use time; only the raw counts are stored.
const STRING_PRIOR_COUNTS: [u32; 256] = [
    491213, 490, 116, 50, 106, 36, 54, 42, 26, 172, 3160, 32,
    30, 2224, 32, 32, 36, 34, 42, 42, 26, 28, 16, 24,
    42, 26, 24, 26, 36, 40, 78, 20, 189361, 3967, 5450, 606,
    1784, 242, 312, 10405, 2988, 2876, 380, 484, 9654, 169547, 52868, 14210,
    78352, 33604, 29299, 19354, 15643, 15123, 12960, 10275, 12014, 11798, 10436, 598,
    19485, 5159, 19680, 478, 430, 131456, 96828, 195928, 140699, 109681, 128519, 101014,
    43464, 158448, 5184, 18833, 91338, 115059, 59950, 72649, 209698, 4911, 122678, 225525,
    143317, 78797, 58455, 70991, 78931, 8787, 7175, 6157, 948, 6117, 182, 356410,
    2232, 858643, 120384, 320772, 396695, 1395210, 140958, 239808, 171560, 657605, 13775, 82576,
    584025, 271173, 706255, 712298, 266835, 10505, 736196, 560606, 907935, 341148, 91173, 58881,
    86175, 164516, 24116, 16984, 922, 17000, 46, 16, 2067, 736, 646, 496,
    873, 900, 616, 759, 1002, 742, 619, 478, 1080, 877, 460, 609,
    1233, 416, 298, 368, 1012, 774, 517, 446, 487, 417, 542, 456,
    783, 466, 446, 490, 759, 585, 317, 226, 532, 513, 476, 606,
    949, 383, 672, 306, 388, 573, 1090, 840, 1075, 514, 590, 522,
    660, 447, 568, 593, 1015, 524, 1310, 881, 1461, 944, 742, 1186,
    14, 28, 230, 248, 88, 44, 42, 78, 20, 24, 30, 36,
    16, 34, 118, 166, 366, 176, 56, 142, 28, 54, 70, 190,
    46, 90, 34, 116, 18, 20, 26, 8, 3032, 1586, 1116, 594,
    1154, 4187, 3030, 1846, 1746, 918, 94, 46, 134, 48, 20, 1262,
    18, 28, 26, 26, 6, 8, 10, 14, 0, 10, 16, 8,
    4, 18, 12, 6,
];

/// The keystream store shipped with the crate. Adding a key for a new
/// build means appending a [[build]] entry to that file; no code changes
/// needed.
pub const KEYS_TOML: &str = include_str!("../keys.toml");

/// One keyed game build from `keys.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildKey {
    /// The apiimo release (semver) that first embedded this keystream.
    pub apiimo_version: String,
    /// Steam depot manifest of the keyed game build, when known.
    pub manifest: Option<u64>,
    /// The game build's depot date, when known.
    pub date: Option<String>,
    /// Free-form provenance note.
    pub note: Option<String>,
    /// The raw keystream, aligned to file offset zero.
    pub key: Vec<u8>,
}

impl BuildKey {
    /// Human-readable identity used in tool output.
    pub fn tag(&self) -> String {
        let manifest = self
            .manifest
            .map(|value| format!("manifest {value}"))
            .unwrap_or_else(|| "unknown manifest".into());
        format!("apiimo {} ({})", self.apiimo_version, manifest)
    }
}

/// Parse the `keys.toml` keystore format. This is a strict parser for the
/// small documented subset the file uses: a `schema = 1` line, then
/// `[[build]]` tables with `apiimo`, optional `manifest`/`date`/`note`,
/// and a `key` given as hex (single line or a multi-line literal string;
/// whitespace is ignored).
pub fn parse_keys_toml(text: &str) -> Result<Vec<BuildKey>, CryptoError> {
    use CryptoError::KeystoreFormat;

    const TRIPLE: &str = "'''";
    let mut schema: Option<u64> = None;
    let mut builds: Vec<BuildKey> = Vec::new();
    let mut in_build = false;
    let mut apiimo: Option<String> = None;
    let mut manifest: Option<u64> = None;
    let mut date: Option<String> = None;
    let mut note: Option<String> = None;
    let mut key_hex = String::new();

    let flush = |builds: &mut Vec<BuildKey>,
                 apiimo: &mut Option<String>,
                 manifest: &mut Option<u64>,
                 date: &mut Option<String>,
                 note: &mut Option<String>,
                 key_hex: &mut String|
     -> Result<(), CryptoError> {
        let Some(version) = apiimo.take() else {
            return Err(KeystoreFormat(
                "[[build]] is missing its apiimo field".into(),
            ));
        };
        if builds
            .iter()
            .any(|existing| existing.apiimo_version == version)
        {
            return Err(KeystoreFormat(format!("duplicate apiimo version {version}")));
        }
        let key = decode_hex(&key_hex.replace(char::is_whitespace, ""))
            .map_err(|_| KeystoreFormat(format!("key for apiimo {version} is not valid hex")))?;
        if key.len() != KEY_PERIOD {
            return Err(KeystoreFormat(format!(
                "key for apiimo {version} is {} bytes, expected {KEY_PERIOD}",
                key.len()
            )));
        }
        builds.push(BuildKey {
            apiimo_version: version,
            manifest: manifest.take(),
            date: date.take(),
            note: note.take(),
            key,
        });
        key_hex.clear();
        Ok(())
    };

    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed == "[[build]]" {
            if in_build {
                flush(
                    &mut builds,
                    &mut apiimo,
                    &mut manifest,
                    &mut date,
                    &mut note,
                    &mut key_hex,
                )?;
            }
            in_build = true;
            continue;
        }
        if !in_build {
            let Some((name, value)) = split_assignment(trimmed) else {
                return Err(KeystoreFormat(format!("unexpected line: {trimmed:?}")));
            };
            if name == "schema" {
                schema = Some(value.parse::<u64>().map_err(|_| {
                    KeystoreFormat(format!("schema is not an integer: {value:?}"))
                })?);
            } else {
                return Err(KeystoreFormat(format!("unexpected top-level field {name:?}")));
            }
            continue;
        }
        let Some((name, value)) = split_assignment(trimmed) else {
            return Err(KeystoreFormat(format!("unexpected line: {trimmed:?}")));
        };
        match name {
            "apiimo" => apiimo = Some(unquote(value)?),
            "date" => date = Some(unquote(value)?),
            "note" => note = Some(unquote(value)?),
            "manifest" => {
                manifest = Some(value.parse::<u64>().map_err(|_| {
                    KeystoreFormat(format!("manifest is not an integer: {value:?}"))
                })?);
            }
            "key" => {
                if let Some(rest) = value.strip_prefix(TRIPLE) {
                    key_hex.push_str(rest);
                    for line in lines.by_ref() {
                        match line.find(TRIPLE) {
                            Some(closing) => {
                                key_hex.push_str(&line[..closing]);
                                break;
                            }
                            None => key_hex.push_str(line),
                        }
                    }
                } else {
                    key_hex.push_str(&unquote(value)?);
                }
            }
            other => {
                return Err(KeystoreFormat(format!("unexpected build field {other:?}")));
            }
        }
    }
    if in_build {
        flush(
            &mut builds,
            &mut apiimo,
            &mut manifest,
            &mut date,
            &mut note,
            &mut key_hex,
        )?;
    }
    if builds.is_empty() {
        return Err(KeystoreFormat("no [[build]] entries found".into()));
    }
    if schema != Some(1) {
        return Err(KeystoreFormat(format!(
            "unsupported keystore schema {schema:?}, expected 1"
        )));
    }
    Ok(builds)
}

fn split_assignment(line: &str) -> Option<(&str, &str)> {
    let (name, value) = line.split_once('=')?;
    Some((name.trim(), value.trim()))
}

fn unquote(value: &str) -> Result<String, CryptoError> {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
        return Ok(value[1..value.len() - 1].to_string());
    }
    Err(CryptoError::KeystoreFormat(format!(
        "expected a quoted string, got {value:?}"
    )))
}

static BUILD_KEYS: OnceLock<Vec<BuildKey>> = OnceLock::new();
static STRING_PRIOR_LOGP: OnceLock<[f64; 256]> = OnceLock::new();

/// Errors raised by the buffer-level crypto routines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    EmptyKey,
    InvalidHex,
    InputTooShort { minimum: usize, actual: usize },
    InvalidPeriod,
    /// The embedded keystore violates the documented keys.toml subset.
    KeystoreFormat(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyKey => write!(f, "keystream must not be empty"),
            Self::InvalidHex => write!(f, "embedded keystream contains invalid hex"),
            Self::InputTooShort { minimum, actual } => write!(
                f,
                "metadata buffer is too short: expected at least {minimum} bytes, got {actual}"
            ),
            Self::InvalidPeriod => write!(f, "keystream period must not be zero"),
            Self::KeystoreFormat(message) => write!(f, "keys.toml: {message}"),
        }
    }
}

impl std::error::Error for CryptoError {}

fn decode_hex(input: &str) -> Result<Vec<u8>, CryptoError> {
    if input.len() % 2 != 0 {
        return Err(CryptoError::InvalidHex);
    }

    let mut bytes = Vec::with_capacity(input.len() / 2);
    let mut chars = input.bytes();
    while let (Some(high), Some(low)) = (chars.next(), chars.next()) {
        let high = (high as char).to_digit(16).ok_or(CryptoError::InvalidHex)?;
        let low = (low as char).to_digit(16).ok_or(CryptoError::InvalidHex)?;
        bytes.push(((high << 4) | low) as u8);
    }
    Ok(bytes)
}

/// Return every keyed build from the embedded keystore, oldest first.
///
/// The keystore is parsed once; a malformed file fails the process here
/// rather than producing silently broken decryption.
pub fn build_keys() -> &'static [BuildKey] {
    BUILD_KEYS.get_or_init(|| {
        parse_keys_toml(KEYS_TOML).expect("embedded keys.toml is valid")
    })
}

/// Return every keystream recovered for a known Aniimo build, oldest first.
pub fn embedded_keys() -> Vec<Vec<u8>> {
    build_keys().iter().map(|build| build.key.clone()).collect()
}

/// Return the build tag for a key returned by [`select_embedded_key`] or
/// [`embedded_keys`].
pub fn embedded_key_tag(key: &[u8]) -> Option<String> {
    build_keys()
        .iter()
        .find(|build| build.key.as_slice() == key)
        .map(|build| build.tag())
}

/// XOR a buffer against a repeating key, starting at `phase` in that key.
pub fn xor_repeating(input: &[u8], key: &[u8], phase: usize) -> Result<Vec<u8>, CryptoError> {
    if key.is_empty() {
        return Err(CryptoError::EmptyKey);
    }

    Ok(input
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ key[(phase + index) % key.len()])
        .collect())
}

/// Decrypt the body after the 256-byte metadata header.
pub fn decrypt_body(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < HEADER_SIZE {
        return Err(CryptoError::InputTooShort {
            minimum: HEADER_SIZE,
            actual: ciphertext.len(),
        });
    }
    xor_repeating(&ciphertext[HEADER_SIZE..], key, HEADER_SIZE)
}

/// Decrypt a complete metadata buffer while preserving the source's header
/// slot as zero bytes for callers that will rebuild it.
pub fn decrypt_metadata(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let body = decrypt_body(ciphertext, key)?;
    let mut plaintext = vec![0; HEADER_SIZE];
    plaintext.extend_from_slice(&body);
    Ok(plaintext)
}

/// Decrypt with the oldest keyed build's keystream (the launch build).
pub fn decrypt_with_embedded_key(ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = build_keys()
        .first()
        .expect("the embedded keystore is never empty")
        .key
        .clone();
    decrypt_metadata(ciphertext, &key)
}

fn printable(byte: u8) -> bool {
    (32..127).contains(&byte)
}

fn decrypt_whole(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    xor_repeating(ciphertext, key, 0)
}

fn candidate_is_printable(ciphertext: &[u8], positions: &[usize], candidate: u8) -> usize {
    positions
        .iter()
        .filter(|&&position| printable(ciphertext[position] ^ candidate))
        .count()
}

/// Recover a repeating XOR key using the statistical fallback from the
/// Python implementation.
///
/// The returned key is aligned to file offset zero. The algorithm is intended
/// for a new build whose embedded key no longer produces a readable string
/// table; known builds should use [`embedded_key`] directly.
pub fn recover_key(ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    recover_key_with_period(ciphertext, KEY_PERIOD)
}

/// Recover a repeating XOR key with a caller-provided period. This is public
/// mainly to make the statistical routine testable on synthetic fixtures.
pub fn recover_key_with_period(ciphertext: &[u8], period: usize) -> Result<Vec<u8>, CryptoError> {
    if period == 0 {
        return Err(CryptoError::InvalidPeriod);
    }

    let length = ciphertext.len();
    let mut key = vec![0_u8; period];

    for (remainder, key_byte) in key.iter_mut().enumerate() {
        let mut counts = [0_usize; 256];
        let mut position = remainder;
        while position < length {
            counts[ciphertext[position] as usize] += 1;
            position += period;
        }
        let mut best = 0;
        for (candidate, count) in counts.iter().enumerate().skip(1) {
            if *count > counts[best] {
                best = candidate;
            }
        }
        *key_byte = best as u8;
    }

    if length >= 4 && period >= 4 {
        let sanity = SANITY.to_le_bytes();
        for index in 0..4 {
            key[index] = ciphertext[index] ^ sanity[index];
        }
    }
    if length >= 8 && period >= 8 {
        let version = VERSION.to_le_bytes();
        for index in 0..4 {
            key[4 + index] = ciphertext[4 + index] ^ version[index];
        }
    }

    let mut decrypted = decrypt_whole(ciphertext, &key)?;
    let printable_window_start = 0x60_000;
    let printable_window_end = 0x74_0000.min(length);

    for _ in 0..3 {
        let mut good = vec![false; length];
        let mut block_start = printable_window_start;
        while block_start < printable_window_end {
            let block_end = (block_start + 0x1000).min(length);
            let block = &decrypted[block_start..block_end];
            let printable_count = block.iter().filter(|&&byte| printable(byte)).count();
            if printable_count * 10 > block.len() * 6 {
                good[block_start..block_end].fill(true);
            }
            block_start += 0x1000;
        }

        let positions: Vec<usize> = good
            .iter()
            .enumerate()
            .filter_map(|(position, &is_good)| is_good.then_some(position))
            .collect();
        if positions.is_empty() {
            break;
        }

        for (remainder, key_byte) in key.iter_mut().enumerate() {
            let selected: Vec<usize> = positions
                .iter()
                .copied()
                .filter(|position| position % period == remainder)
                .collect();
            if selected.len() < 100 {
                continue;
            }

            let mut best_candidate = *key_byte as usize;
            let mut best_count =
                candidate_is_printable(ciphertext, &selected, best_candidate as u8);
            for candidate in 0..256 {
                let count = candidate_is_printable(ciphertext, &selected, candidate as u8);
                if count > best_count {
                    best_count = count;
                    best_candidate = candidate;
                }
            }
            if best_count * 10 > selected.len() * 9 {
                *key_byte = best_candidate as u8;
            }
        }

        decrypted = decrypt_whole(ciphertext, &key)?;
    }

    let segment_start = 0x70_000.min(length);
    let segment_end = 0x71_0000.min(length);
    let segment = &decrypted[segment_start..segment_end];

    let mut trigrams = std::collections::HashMap::<u32, usize>::new();
    let mut run_start = None;
    for index in 0..=segment.len() {
        let is_printable = index < segment.len() && printable(segment[index]);
        match (run_start, is_printable) {
            (None, true) => run_start = Some(index),
            (Some(start), false) => {
                let run_length = index - start;
                if run_length >= 16 {
                    for offset in start..(index - 2) {
                        let value = (u32::from(segment[offset]) << 16)
                            | (u32::from(segment[offset + 1]) << 8)
                            | u32::from(segment[offset + 2]);
                        *trigrams.entry(value).or_default() += 1;
                    }
                }
                run_start = None;
            }
            _ => {}
        }
    }

    if !trigrams.is_empty() {
        let total: usize = trigrams.values().sum();
        let default_log_probability = 1e-9_f64.ln();
        let positions_for = |remainder: usize| -> Vec<usize> {
            let mut positions = Vec::new();
            let mut position = remainder;
            while position < segment_end.saturating_sub(2) {
                if position >= segment_start + 2 {
                    positions.push(position);
                }
                position += period;
            }
            positions
        };
        let score = |positions: &[usize], candidate: u8| -> f64 {
            let mut result = 0.0;
            for &position in positions {
                let context = [
                    decrypted[position - 2],
                    decrypted[position - 1],
                    candidate,
                    decrypted[position + 1],
                    decrypted[position + 2],
                ];
                let values = [
                    (u32::from(context[0]) << 16)
                        | (u32::from(context[1]) << 8)
                        | u32::from(context[2]),
                    (u32::from(context[1]) << 16)
                        | (u32::from(context[2]) << 8)
                        | u32::from(context[3]),
                    (u32::from(context[2]) << 16)
                        | (u32::from(context[3]) << 8)
                        | u32::from(context[4]),
                ];
                for value in values {
                    let probability = trigrams
                        .get(&value)
                        .map(|count| (*count as f64 / total as f64).ln())
                        .unwrap_or(default_log_probability);
                    result += probability;
                }
            }
            result
        };

        for (remainder, key_byte) in key.iter_mut().enumerate() {
            let positions = positions_for(remainder);
            if positions.len() < 200 {
                continue;
            }

            let mut best_candidate = *key_byte;
            let mut best_score = score(&positions, best_candidate);
            for candidate in 0..=u8::MAX {
                if candidate == best_candidate {
                    continue;
                }
                let printable_count = positions
                    .iter()
                    .filter(|&&index| printable(ciphertext[index] ^ candidate))
                    .count();
                if printable_count * 100 < positions.len() * 93 {
                    continue;
                }
                let candidate_score = score(&positions, candidate);
                if candidate_score > best_score + 1.0 {
                    best_score = candidate_score;
                    best_candidate = candidate;
                }
            }
            *key_byte = best_candidate;
        }
    }

    if length >= 4 && period >= 4 {
        let sanity = SANITY.to_le_bytes();
        for index in 0..4 {
            key[index] = ciphertext[index] ^ sanity[index];
        }
    }
    if length >= 8 && period >= 8 {
        let version = VERSION.to_le_bytes();
        for index in 0..4 {
            key[4 + index] = ciphertext[4 + index] ^ version[index];
        }
    }

    Ok(key)
}

/// Start of the ciphertext window used to test candidate keys.
const SELECT_WINDOW_START: usize = 0x6_0000;
/// End of the ciphertext window used to test candidate keys.
const SELECT_WINDOW_END: usize = 0x7_0000;
/// Minimum printable rate over the selection window for a key match.
const SELECT_MIN_RATE: f64 = 0.75;

/// Log-probability of each byte under the string-section distribution of
/// known Aniimo builds (stringLiteralData plus string heaps, all builds).
pub fn string_prior_logp() -> &'static [f64; 256] {
    STRING_PRIOR_LOGP.get_or_init(|| {
        let total: u64 = STRING_PRIOR_COUNTS
            .iter()
            .map(|count| u64::from(*count))
            .sum();
        let mut logp = [0.0_f64; 256];
        for (byte, count) in STRING_PRIOR_COUNTS.iter().enumerate() {
            logp[byte] = ((f64::from(*count) + 1.0) / (total as f64 + 256.0)).ln();
        }
        logp
    })
}

fn window_printable_rate(ciphertext: &[u8], key: &[u8]) -> f64 {
    let start = SELECT_WINDOW_START.min(ciphertext.len());
    let end = SELECT_WINDOW_END.min(ciphertext.len());
    let (window, phase) = if end > start {
        (&ciphertext[start..end], start)
    } else {
        (ciphertext, 0)
    };
    if window.is_empty() {
        return 0.0;
    }
    let hits = window
        .iter()
        .enumerate()
        .filter(|(index, byte)| printable(*byte ^ key[(phase + index) % key.len()]))
        .count();
    hits as f64 / window.len() as f64
}

/// Pick the known-build keystream that decrypts the string window of
/// `ciphertext`, or `None` when no embedded key matches (a fresh update).
pub fn select_embedded_key(ciphertext: &[u8]) -> Option<&'static [u8]> {
    let keys = build_keys();
    let mut best = None;
    let mut best_rate = f64::NEG_INFINITY;
    for build in keys {
        let rate = window_printable_rate(ciphertext, &build.key);
        if rate > best_rate {
            best_rate = rate;
            best = Some(build);
        }
    }
    if best_rate < SELECT_MIN_RATE {
        None
    } else {
        best.map(|build| build.key.as_slice())
    }
}

/// Refine an approximate repeating-XOR key against the embedded string byte
/// distribution.
///
/// The statistical [`recover_key`] pass often lands within a few hundred
/// wrong residues while still leaving garbled bytes throughout the string
/// tables. This refinement marks 4 KiB blocks whose current decryption is at
/// least 60% printable, then for every key residue re-picks the byte that
/// makes the corresponding ciphertext column most likely under the string
/// distribution of known builds, iterating until the key is stable.
pub fn refine_key(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.is_empty() {
        return Err(CryptoError::EmptyKey);
    }
    let logp = string_prior_logp();
    let mut current = key.to_vec();
    for _ in 0..6 {
        let decrypted = xor_repeating(ciphertext, &current, 0)?;
        let mut histograms = vec![[0_u64; 256]; current.len()];
        let mut samples = vec![0_usize; current.len()];
        let mut block_start = 0;
        while block_start < ciphertext.len() {
            let block_end = (block_start + 0x1000).min(ciphertext.len());
            let printable_count = decrypted[block_start..block_end]
                .iter()
                .filter(|&&byte| printable(byte))
                .count();
            if printable_count * 10 > (block_end - block_start) * 6 {
                for offset in block_start..block_end {
                    let residue = offset % current.len();
                    histograms[residue][ciphertext[offset] as usize] += 1;
                    samples[residue] += 1;
                }
            }
            block_start = block_end;
        }

        let mut changed = 0;
        for residue in 0..current.len() {
            if samples[residue] < 500 {
                continue;
            }
            let mut best = current[residue] as usize;
            let mut best_score = f64::NEG_INFINITY;
            for candidate in 0..256 {
                let mut score = 0.0;
                for byte in 0..256 {
                    let count = histograms[residue][byte];
                    if count != 0 {
                        score += count as f64 * logp[byte ^ candidate];
                    }
                }
                if score > best_score {
                    best_score = score;
                    best = candidate;
                }
            }
            if best != current[residue] as usize {
                current[residue] = best as u8;
                changed += 1;
            }
        }
        if changed == 0 {
            break;
        }
    }
    Ok(current)
}

/// Recover a repeating-XOR key for an unknown build: statistical seed pass
/// followed by prior-guided refinement.
pub fn recover_key_refined(ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let seed = recover_key(ciphertext)?;
    refine_key(ciphertext, &seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_keystore_decodes_to_expected_period() {
        assert!(build_keys().iter().all(|b| b.key.len() == KEY_PERIOD));
    }

    #[test]
    fn embedded_keystore_is_complete_and_unique() {
        let builds = build_keys();
        assert!(builds.len() >= 2, "both known builds must stay keyed");
        for build in builds {
            assert_eq!(build.key.len(), KEY_PERIOD);
            assert!(!build.apiimo_version.is_empty());
        }
        for pair in builds.windows(2) {
            assert_ne!(
                pair[0].apiimo_version, pair[1].apiimo_version,
                "keystore versions must be unique"
            );
        }
        assert_eq!(
            embedded_key_tag(&builds[0].key),
            Some(builds[0].tag())
        );
        assert_eq!(embedded_key_tag(&[0_u8; 8]), None);
    }

    #[test]
    fn parse_keys_toml_rejects_bad_input() {
        use CryptoError::KeystoreFormat;

        assert!(matches!(
            parse_keys_toml("schema = 1\n"),
            Err(KeystoreFormat(_))
        ));
        let duplicated = KEYS_TOML.replace(
            "apiimo = \"0.2.0\"",
            "apiimo = \"0.1.0\"",
        );
        assert!(matches!(
            parse_keys_toml(&duplicated),
            Err(KeystoreFormat(_))
        ));
        let truncated = KEYS_TOML.replace(
            "schema = 1",
            "schema = 2",
        );
        assert!(matches!(
            parse_keys_toml(&truncated),
            Err(KeystoreFormat(_))
        ));
    }

    fn lcg_byte(state: &mut u64) -> u8 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (*state >> 33) as u8
    }

    fn synthetic_printable(len: usize) -> Vec<u8> {
        let alphabet = b"abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.<>()/";
        let mut state = 0x853c_49e6_748f_ea9b_u64;
        (0..len)
            .map(|_| alphabet[lcg_byte(&mut state) as usize % alphabet.len()])
            .collect()
    }

    #[test]
    fn select_embedded_key_matches_known_builds() {
        let plaintext = synthetic_printable(0x2_0000);
        for key in embedded_keys() {
            let ciphertext = xor_repeating(&plaintext, &key, 0).unwrap();
            let selected = select_embedded_key(&ciphertext).expect("key should match");
            assert_eq!(selected, key.as_slice());
        }
        let mut state = 0x243f_6a88_85a3_08d3_u64;
        let noise: Vec<u8> = (0..0x2_0000)
            .map(|_| lcg_byte(&mut state) ^ 0xa5)
            .collect();
        assert!(select_embedded_key(&noise).is_none());
    }

    #[test]
    fn refine_key_repairs_corrupted_residues() {
        let period = 64;
        let plaintext = synthetic_printable(0x4_0000);
        let mut state = 0x1319_8a2e_0370_7344_u64;
        let true_key: Vec<u8> = (0..period).map(|_| lcg_byte(&mut state)).collect();
        let ciphertext = xor_repeating(&plaintext, &true_key, 0).unwrap();

        let mut corrupted = true_key.clone();
        for residue in (0..period).step_by(4) {
            corrupted[residue] ^= 0x5a;
        }
        let refined = refine_key(&ciphertext, &corrupted).unwrap();
        let repaired = (0..period)
            .filter(|residue| refined[*residue] == true_key[*residue])
            .count();
        assert!(repaired >= period - 1, "repaired {repaired} of {period}");

        let decrypted = xor_repeating(&ciphertext, &refined, 0).unwrap();
        let rate = decrypted
            .iter()
            .filter(|&&byte| printable(byte))
            .count() as f64
            / decrypted.len() as f64;
        assert!(rate >= 0.97, "printable rate {rate}");
    }

    #[test]
    fn body_xor_is_reversible() {
        let mut ciphertext = vec![0_u8; HEADER_SIZE + 37];
        for (index, byte) in ciphertext.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(17);
        }
        let key = &build_keys()[0].key;
        let plaintext_body = ciphertext[HEADER_SIZE..].to_vec();
        let encrypted_body = xor_repeating(&ciphertext[HEADER_SIZE..], key, HEADER_SIZE).unwrap();
        ciphertext[HEADER_SIZE..].copy_from_slice(&encrypted_body);
        let decrypted = decrypt_body(&ciphertext, key).unwrap();
        assert_eq!(decrypted, plaintext_body);
    }

    #[test]
    fn recover_key_honors_known_header_bytes() {
        let mut encrypted = vec![0_u8; 32];
        for (index, byte) in encrypted.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let key = recover_key_with_period(&encrypted, 16).unwrap();
        for index in 0..4 {
            assert_eq!(encrypted[index] ^ key[index], SANITY.to_le_bytes()[index]);
        }
        for index in 0..4 {
            assert_eq!(
                encrypted[4 + index] ^ key[4 + index],
                VERSION.to_le_bytes()[index]
            );
        }
    }
}
