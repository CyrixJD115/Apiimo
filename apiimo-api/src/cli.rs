//! Command-line front end mirroring the original Python tool.
//!
//! [`parse`] accepts the same command surface (`dump`, `classes <regex>`,
//! `methods <regex>`, `fields <ClassRegex>`, `addr <SubStr>`, `str <regex>`,
//! `va2off <va_hex>`, `off2va <off_hex>`, `patch <va_hex> <hexbytes>`,
//! `discover`) with `--out <dir>` and `--game <dir>` accepted anywhere,
//! just like the Python entry point. [`render`] turns an [`Output`](crate::Output)
//! into the human-readable text the Python tool printed.

use std::path::PathBuf;

use crate::{Command, Output};

/// Errors produced while parsing command-line arguments.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("missing argument for {0}")]
    MissingArgument(&'static str),
    #[error("invalid hexadecimal value {value:?}: {reason}")]
    InvalidHex { value: String, reason: String },
    #[error("unknown command or bad usage: {0}")]
    UnknownCommand(String),
}

/// A parsed command line: the command plus any global overrides.
#[derive(Debug, Clone, PartialEq)]
pub struct Invocation {
    pub command: Command,
    pub game_dir: Option<PathBuf>,
    pub output_dir: Option<PathBuf>,
    pub dumper_command: Option<PathBuf>,
    /// `true` when the caller passed no arguments at all and printed the
    /// usage text instead of running a command.
    pub help_only: bool,
}

/// Parse arguments the way the Python tool's `main()` does.
pub fn parse<I, S>(args: I) -> Result<Invocation, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args: Vec<String> = args.into_iter().map(Into::into).collect();

    let mut invocation = Invocation {
        command: Command::Dump,
        game_dir: None,
        output_dir: None,
        dumper_command: None,
        help_only: false,
    };

    let take_option = |flag: &'static str,
                       invocation: &mut Invocation,
                       args: &mut Vec<String>|
     -> Result<(), CliError> {
        let Some(index) = args.iter().position(|arg| arg == flag) else {
            return Ok(());
        };
        let value = args
            .get(index + 1)
            .ok_or(CliError::MissingArgument(flag))?
            .clone();
        let path = Some(PathBuf::from(value));
        match flag {
            "--out" => invocation.output_dir = path,
            "--game" => invocation.game_dir = path,
            "--dumper" => invocation.dumper_command = path,
            _ => unreachable!("flag is one of the three above"),
        }
        args.drain(index..=index + 1);
        Ok(())
    };
    take_option("--out", &mut invocation, &mut args)?;
    take_option("--game", &mut invocation, &mut args)?;
    take_option("--dumper", &mut invocation, &mut args)?;

    if args.is_empty() {
        invocation.help_only = true;
        return Ok(invocation);
    }

    let name = args[0].as_str();
    let arg = |index: usize, what: &'static str| -> Result<&str, CliError> {
        args.get(index)
            .map(String::as_str)
            .ok_or(CliError::MissingArgument(what))
    };

    invocation.command = match name {
        "dump" => Command::Dump,
        "discover" => Command::Discover,
        "classes" => Command::classes(arg(1, "classes <regex>")?),
        "methods" => Command::methods(arg(1, "methods <regex>")?),
        "fields" => Command::fields(arg(1, "fields <ClassRegex>")?),
        "addr" => Command::addr(arg(1, "addr <SubStr>")?),
        "str" => Command::str(arg(1, "str <regex>")?),
        "va2off" => Command::Va2Off {
            va: parse_hex(arg(1, "va2off <va_hex>")?)?,
        },
        "off2va" => Command::Off2Va {
            offset: parse_hex(arg(1, "off2va <off_hex>")?)?,
        },
        "patch" => Command::Patch {
            va: parse_hex(arg(1, "patch <va_hex> <hexbytes>")?)?,
            hex: arg(2, "patch <va_hex> <hexbytes>")?.to_string(),
        },
        "xdf" => Command::Xdf {
            container: PathBuf::from(arg(1, "xdf <path> [filter]")?),
            filter: args.get(2).cloned(),
            limit: 100,
        },
        "gate-handshake" => {
            let target = arg(1, "gate-handshake [host:port]")?;
            let (host, port) = match target.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse().unwrap_or(10000)),
                None => (target.to_string(), 10000),
            };
            Command::GateHandshake { host, port }
        }
        "gate-probe" => {
            let target = arg(1, "gate-probe [host:port]")?;
            let (host, port) = match target.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse().unwrap_or(10000)),
                None => (target.to_string(), 10000),
            };
            Command::GateProbe { host, port }
        }
        "xdf-cat" => Command::XdfCat {
            container: PathBuf::from(arg(1, "xdf-cat <path> <entry>")?),
            entry: arg(2, "xdf-cat <path> <entry>")?.to_string(),
        },
        "lua-strings" => Command::XdfStrings {
            container: PathBuf::from(arg(1, "lua-strings <path> <entry>")?),
            entry: arg(2, "lua-strings <path> <entry>")?.to_string(),
            limit: 5000,
        },
        other => return Err(CliError::UnknownCommand(other.to_string())),
    };
    Ok(invocation)
}

/// Accept `0x`-prefixed or bare hexadecimal like Python's `int(value, 16)`.
pub fn parse_hex(value: &str) -> Result<u64, CliError> {
    let trimmed = value.trim().trim_start_matches("0x");
    u64::from_str_radix(trimmed, 16).map_err(|error| CliError::InvalidHex {
        value: value.to_string(),
        reason: error.to_string(),
    })
}

/// Render an [`Output`] in the style of the Python tool's prints.
pub fn render(output: &Output) -> String {
    let mut text = String::new();
    match output {
        Output::Dump(report) => {
            use std::fmt::Write;
            let report = report.as_ref();
            let _ = writeln!(
                text,
                "[1/3] metadata {}",
                if report.was_encrypted {
                    "decrypted"
                } else {
                    "was already decrypted; used as-is"
                }
            );
            let _ = writeln!(
                text,
                "      sanitized {} default-value records",
                report.fixed_defaults
            );
            let _ = writeln!(
                text,
                "[2/3] rebuilt metadata: {}",
                report.decrypted_metadata.display()
            );
            let _ = writeln!(
                text,
                "[3/3] Il2CppDumper ({}):",
                report.dumper_command.display()
            );
            for file in &report.generated_files {
                let _ = writeln!(text, "      {:<24} {:>12} bytes", file.name, file.size);
            }
            let _ = writeln!(
                text,
                "      DummyDll assemblies:     {}",
                report.dummy_dll_assemblies
            );
            let _ = writeln!(
                text,
                "      done ({} per-image errors)",
                report.dumper_error_count
            );
        }
        Output::Sections(sections) => {
            use std::fmt::Write;
            for section in sections {
                let _ = writeln!(
                    text,
                    "  {:<42} [{:#010x}, {:#010x}) {:#x}",
                    section.name,
                    section.offset,
                    section.offset + section.size,
                    section.size
                );
            }
            let _ = writeln!(
                text,
                "  (experimental - full dynamic discovery is a work in progress)"
            );
        }
        Output::Classes(matches) => {
            use std::fmt::Write;
            for entry in matches {
                let qualified = if entry.namespace.is_empty() {
                    entry.name.clone()
                } else {
                    format!("{}.{}", entry.namespace, entry.name)
                };
                let type_index = entry
                    .type_index
                    .map(|index| index.to_string())
                    .unwrap_or_else(|| "?".into());
                let _ = writeln!(text, "{qualified}  [type {type_index}]");
            }
            let _ = writeln!(text, "-- {} classes", matches.len());
        }
        Output::Methods(matches) => {
            use std::fmt::Write;
            for method in matches {
                let _ = writeln!(text, "{:#x}  {}", method.va, method.signature);
            }
            let _ = writeln!(text, "-- {} methods", matches.len());
        }
        Output::Fields(lines) => {
            for line in lines {
                text.push_str(line);
                text.push('\n');
            }
        }
        Output::Addresses(matches) => {
            use std::fmt::Write;
            for entry in matches {
                let _ = writeln!(text, "{:#x}  {}", entry.address, entry.name);
            }
            let _ = writeln!(text, "-- {} methods", matches.len());
        }
        Output::Strings(matches) => {
            use std::fmt::Write;
            for entry in matches {
                let _ = writeln!(text, "{:#x}  {:?}", entry.address, entry.value);
            }
            let _ = writeln!(text, "-- {} literals", matches.len());
        }
        Output::VaToOffset(offset) => text = format!("{offset:#x}\n"),
        Output::OffsetToVa(va) => text = format!("{va:#x}\n"),
        Output::Patched {
            byte_count,
            file_offset,
            ..
        } => text = format!("patched {byte_count} bytes at file offset {file_offset:#x}\n"),
        Output::XdfEntries(entries) => {
            use std::fmt::Write;
            for entry in entries {
                let _ = writeln!(
                    text,
                    "{:>12}  {:>12}  {}",
                    entry.uncompressed_size, entry.compressed_size, entry.name
                );
            }
            let _ = writeln!(text, "-- {} entries", entries.len());
        }
        Output::GateHandshakeResult {
            host,
            token,
            key_hex,
            frames,
        } => {
            use std::fmt::Write;
            let _ = writeln!(text, "gate {host} anonymous handshake:");
            let _ = writeln!(text, "  token          : {token} ({token:#x})");
            let _ = writeln!(text, "  our session key: {key_hex}");
            for frame in frames {
                let _ = writeln!(text, "  frame {frame}");
            }
            if frames.is_empty() {
                let _ = writeln!(text, "  (no server bytes after confirm — silent ack?)");
            }
        }
        Output::GateProbeResult {
            host,
            port,
            token,
            gate_info,
            other,
        } => {
            use std::fmt::Write;
            let _ = writeln!(text, "gate {host}:{port}");
            match token {
                Some(token) => {
                    let _ = writeln!(text, "  encrypt token : {token} ({token:#x})");
                }
                None => {
                    let _ = writeln!(text, "  encrypt token : <none received>");
                }
            }
            if let Some(info) = gate_info {
                let _ = writeln!(text, "  gate info     : {info}");
            }
            for (method, size) in other {
                let _ = writeln!(text, "  other frame   : method={method} bytes={size}");
            }
        }
        Output::XdfBytes(bytes) => {
            use std::io::Write;
            std::io::stdout().write_all(bytes).expect("stdout write");
        }
        Output::LuaStrings {
            chunk_name,
            version,
            strings,
        } => {
            use std::fmt::Write;
            let _ = writeln!(
                text,
                "// LuaJIT {version} chunk: {}",
                chunk_name.as_deref().unwrap_or("?")
            );
            for line in strings {
                let _ = writeln!(text, "{line}");
            }
            let _ = writeln!(text, "-- {} strings", strings.len());
        }
    }
    text
}

/// Usage text mirroring the Python tool's module docstring.
pub fn usage() -> String {
    String::from(
        "Apiimo - Aniimo (Unity IL2CPP) reverse engineering toolkit.\n\n\
         Commands:\n\
         \x20 dump                        full pipeline -> <out> (default: <game>/.dump)\n\
         \x20 classes <regex>             list matching classes\n\
         \x20 methods <regex>             list matching methods with VA\n\
         \x20 fields <ClassRegex>         dump a class layout (fields + offsets)\n\
         \x20 addr <SubStr>               resolve method addresses from script.json\n\
         \x20 str <regex>                 search string literals\n\
         \x20 va2off <va_hex>             GameAssembly.dll VA -> file offset\n\
         \x20 off2va <off_hex>            file offset -> VA\n\
         \x20 patch <va_hex> <hexbytes>   patch GameAssembly.dll in place\n\
         \x20 discover                    experimental: rediscover section layout\n\
         \x20 xdf <path> [filter]         list XDF container entries (LuaScripts.xdf)\n\
         \x20 lua-strings <path> <entry>  dump strings of a LuaJIT entry in an XDF\n\
         \x20 xdf-cat <path> <entry>      write one XDF entry's raw bytes to stdout\n\
         \x20 gate-probe [host:port]       request an encrypt token from a gate\n\
         \x20 gate-handshake [host:port]    anonymous session-key exchange\n\n\
         Options:\n\
         \x20 --out <dir>                 output directory (default: <game>/.dump)\n\
         \x20 --game <dir>                game root (default: APIIMO_GAME or auto-discovery)\n\
         \x20 --dumper <path>             Il2CppDumper executable (default: il2cpp-dumper on PATH)\n\
         \x20 --json                      print structured JSON instead of text\n",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_python_style_invocations() {
        let invocation = parse(["classes", "--out", "/tmp/d", "AntiCheat"]).unwrap();
        assert_eq!(
            invocation.command,
            Command::Classes {
                pattern: "AntiCheat".into(),
                limit: 100
            }
        );
        assert_eq!(invocation.output_dir, Some(PathBuf::from("/tmp/d")));

        let invocation = parse([
            "dump",
            "--dumper",
            "/usr/bin/dotnet",
            "--game",
            "/games/Aniimo",
        ])
        .unwrap();
        assert_eq!(invocation.command, Command::Dump);
        assert_eq!(
            invocation.dumper_command,
            Some(PathBuf::from("/usr/bin/dotnet"))
        );
        assert_eq!(invocation.game_dir, Some(PathBuf::from("/games/Aniimo")));

        let invocation = parse(["patch", "0x184455A60", "90 90"]).unwrap();
        assert_eq!(
            invocation.command,
            Command::Patch {
                va: 0x1844_55A60,
                hex: "90 90".into()
            }
        );

        let invocation = parse(["va2off", "184455A60"]).unwrap();
        assert_eq!(invocation.command, Command::Va2Off { va: 0x1844_55A60 });

        assert!(parse(std::iter::empty::<&str>()).unwrap().help_only);
        assert!(parse(["wat"]).is_err());
        assert!(parse(["classes"]).is_err());
    }

    #[test]
    fn renders_class_matches_like_python() {
        let output = Output::Classes(vec![crate::ClassMatch {
            namespace: "NTESHTPSec".into(),
            name: "AntiCheatResult".into(),
            type_index: Some(27781),
        }]);
        assert_eq!(
            render(&output),
            "NTESHTPSec.AntiCheatResult  [type 27781]\n-- 1 classes\n"
        );
    }
}
