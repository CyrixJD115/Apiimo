//! Recover the repeating-XOR keystream of an Aniimo metadata file.
//!
//! Usage: cargo run --release -p apiimo-crypto --example recover -- <metadata> [output]
//!
//! Known builds are served instantly from the embedded keystreams; an
//! unknown build falls back to statistical recovery plus prior-guided
//! refinement. Prints the implied header bytes, printable-rate stats for the
//! string windows, and the decrypted 256-byte header as u32 words so the
//! section layout of a new build can be read directly. Writes the decrypted
//! file to `output` when given. The game scrambles the header slot on
//! purpose, so the sanity/version lines are informational only; the header
//! gets rebuilt downstream anyway.

use std::env;
use std::fs;
use std::process::ExitCode;

fn printable_rate(buf: &[u8]) -> f64 {
    let hits = buf
        .iter()
        .filter(|&&b| (32..127).contains(&b))
        .count();
    hits as f64 / buf.len() as f64
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let mut paths: Vec<String> = Vec::new();
    let mut force_recover = false;
    for arg in args.iter().skip(1) {
        if arg == "--recover" {
            force_recover = true;
        } else {
            paths.push(arg.clone());
        }
    }
    if paths.is_empty() {
        eprintln!("usage: recover [--recover] <metadata> [output]");
        eprintln!("  --recover  skip embedded-key selection and force statistical recovery");
        return ExitCode::FAILURE;
    }
    let raw = match fs::read(&paths[0]) {
        Ok(raw) => raw,
        Err(err) => {
            eprintln!("failed to read {}: {err}", paths[0]);
            return ExitCode::FAILURE;
        }
    };

    let key = if force_recover {
        None
    } else {
        apiimo_crypto::select_embedded_key(&raw)
    };
    let key = match key {
        Some(key) => {
            let tag = apiimo_crypto::embedded_key_tag(key).unwrap_or_else(|| "unknown build".into());
            eprintln!("embedded key matched: {tag}");
            key.to_vec()
        }
        None => {
            eprintln!("no embedded key matched; running statistical recovery");
            let seed = match apiimo_crypto::recover_key(&raw) {
                Ok(seed) => seed,
                Err(err) => {
                    eprintln!("recovery failed: {err}");
                    return ExitCode::FAILURE;
                }
            };
            eprintln!("seed key: {} bytes; refining with string prior", seed.len());
            match apiimo_crypto::refine_key(&raw, &seed) {
                Ok(key) => key,
                Err(err) => {
                    eprintln!("refinement failed: {err}");
                    return ExitCode::FAILURE;
                }
            }
        }
    };
    eprintln!("using {}-byte key", key.len());

    let whole = match apiimo_crypto::xor_repeating(&raw, &key, 0) {
        Ok(whole) => whole,
        Err(err) => {
            eprintln!("decryption failed: {err}");
            return ExitCode::FAILURE;
        }
    };

    let sanity = u32::from_le_bytes([whole[0], whole[1], whole[2], whole[3]]);
    let version = u32::from_le_bytes([whole[4], whole[5], whole[6], whole[7]]);
    println!("decrypted sanity: {sanity:#010x} (expected {:#010x})", apiimo_crypto::SANITY);
    println!("decrypted version: {version}");

    let windows = [
        (0x6_0000usize, 0x74_0000usize, "string window"),
        (0x7_0000usize, 0x71_0000usize, "trigram segment"),
    ];
    for (start, end, label) in windows {
        let stop = end.min(whole.len());
        println!("{label} {start:#x}..{stop:#x}: printable {:.1}%", printable_rate(&whole[start..stop]) * 100.0);
    }

    println!("decrypted header words:");
    for word in 0..64 {
        let base = word * 4;
        let value = u32::from_le_bytes([
            whole[base],
            whole[base + 1],
            whole[base + 2],
            whole[base + 3],
        ]);
        println!("  [{word:2}] @{base:#04x}: {value:#010x} ({value})");
    }

    if let Some(out) = paths.get(1) {
        if let Err(err) = fs::write(out, &whole) {
            eprintln!("failed to write {out}: {err}");
            return ExitCode::FAILURE;
        }
        eprintln!("wrote {}", out);
    }
    ExitCode::SUCCESS
}
