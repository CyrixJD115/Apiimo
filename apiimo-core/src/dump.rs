use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::error::{io_error, Error};
use crate::metadata::rebuild_metadata;
use crate::paths::{binary_path, metadata_path, output_path, DEC_NAME};
use crate::TYPES_IN_BINARY;

/// Options for the full decrypt/rebuild/Il2CppDumper pipeline.
#[derive(Debug, Clone)]
pub struct DumpOptions {
    pub game_dir: PathBuf,
    pub output_dir: Option<PathBuf>,
    pub dumper_command: OsString,
    pub types_count: u32,
}

impl DumpOptions {
    pub fn new(game_dir: impl Into<PathBuf>) -> Self {
        Self {
            game_dir: game_dir.into(),
            output_dir: None,
            dumper_command: OsString::from("il2cpp-dumper"),
            types_count: TYPES_IN_BINARY,
        }
    }
}

/// A generated output file reported by the pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedFile {
    pub name: String,
    pub size: u64,
}

/// Summary of one dump pipeline run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DumpReport {
    pub output_dir: PathBuf,
    pub decrypted_metadata: PathBuf,
    pub fixed_defaults: usize,
    pub was_encrypted: bool,
    /// The dumper executable/dll actually invoked for this run.
    pub dumper_command: PathBuf,
    pub dumper_succeeded: bool,
    pub dumper_error_count: usize,
    pub generated_files: Vec<GeneratedFile>,
    pub dummy_dll_assemblies: usize,
}

/// Run the Python tool's `dump` pipeline without printing to stdout.
pub fn run_dump(options: &DumpOptions) -> Result<DumpReport, Error> {
    let metadata_file = metadata_path(&options.game_dir);
    let binary_file = binary_path(&options.game_dir);
    let raw = fs::read(&metadata_file).map_err(|source| io_error(&metadata_file, source))?;
    let rebuilt = rebuild_metadata(&raw, options.types_count)?;
    let output_dir = output_path(&options.game_dir, options.output_dir.as_deref())?;
    let decrypted_metadata = output_dir.join(DEC_NAME);
    fs::write(&decrypted_metadata, &rebuilt.metadata)
        .map_err(|source| io_error(&decrypted_metadata, source))?;

    if !binary_file.exists() {
        return Err(Error::MissingFile(binary_file));
    }

    // A .dll dumper path (the dotnet build published from apiimo-il2cpp) is
    // spawned through the dotnet runtime rather than executed directly.
    let mut command = if options
        .dumper_command
        .to_string_lossy()
        .to_ascii_lowercase()
        .ends_with(".dll")
    {
        let mut command = Command::new("dotnet");
        command.arg(&options.dumper_command);
        command
    } else {
        Command::new(&options.dumper_command)
    };
    let output = command
        .arg(&binary_file)
        .arg(&decrypted_metadata)
        .arg(&output_dir)
        .output()
        .map_err(|error| Error::DumperStart(error.to_string()))?;
    let mut log = output.stdout.clone();
    log.extend_from_slice(&output.stderr);
    let log_path = output_dir.join("dumper.log");
    fs::write(&log_path, &log).map_err(|source| io_error(&log_path, source))?;

    let generated_files = ["dump.cs", "script.json", "il2cpp.h", "stringliteral.json"]
        .into_iter()
        .filter_map(|name| {
            let path = output_dir.join(name);
            let size = fs::metadata(&path).ok()?.len();
            Some(GeneratedFile {
                name: name.to_string(),
                size,
            })
        })
        .collect();

    Ok(DumpReport {
        output_dir: output_dir.clone(),
        decrypted_metadata,
        fixed_defaults: rebuilt.fixed_defaults,
        was_encrypted: rebuilt.was_encrypted,
        dumper_command: options.dumper_command.clone().into(),
        dumper_succeeded: output.status.success(),
        dumper_error_count: String::from_utf8_lossy(&output.stdout)
            .matches("Some errors")
            .count(),
        generated_files,
        dummy_dll_assemblies: count_files(&output_dir.join("DummyDll"))?,
    })
}

fn count_files(path: &Path) -> Result<usize, Error> {
    if !path.exists() {
        return Ok(0);
    }
    let mut count = 0;
    let entries = fs::read_dir(path).map_err(|source| io_error(path, source))?;
    for entry in entries {
        let entry = entry.map_err(|source| io_error(path, source))?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            count += count_files(&entry_path)?;
        } else if entry_path.is_file() {
            count += 1;
        }
    }
    Ok(count)
}
