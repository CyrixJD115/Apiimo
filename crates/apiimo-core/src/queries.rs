use std::fs;
use std::path::Path;

use regex::Regex;
use serde_json::Value;

use crate::error::{io_error, json_error, Error};

/// A class/struct/interface match from `dump.cs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassMatch {
    pub namespace: String,
    pub name: String,
    pub type_index: Option<u64>,
}

/// A method match from `dump.cs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodMatch {
    pub class_name: String,
    pub signature: String,
    pub rva: u64,
    pub offset: u64,
    pub va: u64,
}

/// A method address match from `script.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressMatch {
    pub address: u64,
    pub name: String,
}

/// A string literal match from `script.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringLiteralMatch {
    pub address: u64,
    pub value: String,
}

/// Find classes, structs, or interfaces by case-insensitive regex.
pub fn find_classes(
    dump_cs: impl AsRef<Path>,
    pattern: &str,
    limit: usize,
) -> Result<Vec<ClassMatch>, Error> {
    let regex = Regex::new(&format!("(?i:{pattern})"))?;
    let contents = read_text(dump_cs.as_ref())?;
    let namespace_regex = Regex::new(r"^// Namespace: (.*)$")?;
    let declaration_regex = Regex::new(r"(class|struct|interface) (\S+)")?;
    let type_index_regex = Regex::new(r"TypeDefIndex: (\d+)")?;
    let mut namespace = String::new();
    let mut matches = Vec::new();

    for line in contents.lines() {
        if let Some(captures) = namespace_regex.captures(line) {
            namespace = captures[1].trim().to_string();
            continue;
        }
        if line.trim_start().starts_with("//") {
            continue;
        }
        let Some(captures) = declaration_regex.captures(line) else {
            continue;
        };
        let name = captures[2].to_string();
        if !regex.is_match(&name) && !regex.is_match(&namespace) {
            continue;
        }
        matches.push(ClassMatch {
            namespace: namespace.clone(),
            name,
            type_index: type_index_regex
                .captures(line)
                .and_then(|capture| capture[1].parse().ok()),
        });
        if matches.len() >= limit {
            break;
        }
    }
    Ok(matches)
}

/// Find method signatures and their RVA/offset/VA values by regex.
pub fn find_methods(
    dump_cs: impl AsRef<Path>,
    pattern: &str,
    limit: usize,
) -> Result<Vec<MethodMatch>, Error> {
    let regex = Regex::new(&format!("(?i:{pattern})"))?;
    let contents = read_text(dump_cs.as_ref())?;
    let class_regex = Regex::new(r"(class|struct) (\S+)")?;
    let address_regex =
        Regex::new(r"RVA: (0x[0-9A-Fa-f]+) Offset: (0x[0-9A-Fa-f]+) VA: (0x[0-9A-Fa-f]+)")?;
    let lines: Vec<&str> = contents.lines().collect();
    let mut class_name = String::new();
    let mut matches = Vec::new();

    for (index, line) in lines.iter().enumerate() {
        if let Some(captures) = class_regex.captures(line) {
            if line.contains("// TypeDefIndex") {
                class_name = captures[2].to_string();
                continue;
            }
        }
        if !line.contains("RVA:") || index + 1 >= lines.len() {
            continue;
        }
        let signature = lines[index + 1].trim();
        if !regex.is_match(signature) && !regex.is_match(&class_name) {
            continue;
        }
        let Some(captures) = address_regex.captures(line) else {
            continue;
        };
        matches.push(MethodMatch {
            class_name: class_name.clone(),
            signature: signature.to_string(),
            rva: parse_hex(&captures[1])?,
            offset: parse_hex(&captures[2])?,
            va: parse_hex(&captures[3])?,
        });
        if matches.len() >= limit {
            break;
        }
    }
    Ok(matches)
}

/// Return the same bounded class-layout text shown by the Python `fields`
/// command.
pub fn find_fields(
    dump_cs: impl AsRef<Path>,
    class_pattern: &str,
    limit: usize,
) -> Result<Vec<String>, Error> {
    let regex = Regex::new(&format!("(?i:{class_pattern})"))?;
    let contents = read_text(dump_cs.as_ref())?;
    let class_regex = Regex::new(r"(class|struct) (\S+)")?;
    let mut show = false;
    let mut lines = Vec::new();

    for line in contents.lines() {
        if let Some(captures) = class_regex.captures(line) {
            if line.contains("// TypeDefIndex")
                || line.starts_with("public")
                || line.starts_with("internal")
            {
                show = regex.is_match(&captures[2]);
            }
        }
        if show {
            lines.push(line.trim_end().to_string());
            if lines.len() >= limit {
                break;
            }
        }
    }
    Ok(lines)
}

/// Load the Il2CppDumper script JSON from an output directory.
pub fn load_script(output_dir: impl AsRef<Path>) -> Result<Value, Error> {
    let path = output_dir.as_ref().join("script.json");
    if !path.exists() {
        return Err(Error::MissingFile(path));
    }
    let bytes = fs::read(&path).map_err(|source| io_error(&path, source))?;
    serde_json::from_slice(&bytes).map_err(|source| json_error(path, source))
}

/// Search `ScriptMethod` entries by case-insensitive substring.
pub fn find_addresses(
    script: &Value,
    substring: &str,
    limit: usize,
) -> Result<Vec<AddressMatch>, Error> {
    let needle = substring.to_lowercase();
    let methods = script
        .get("ScriptMethod")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::InvalidMetadata("script.json has no ScriptMethod array".into()))?;
    let mut matches = Vec::new();
    for method in methods {
        let Some(name) = method.get("Name").and_then(Value::as_str) else {
            continue;
        };
        if !name.to_lowercase().contains(&needle) {
            continue;
        }
        let Some(address) = json_u64(method.get("Address")) else {
            continue;
        };
        matches.push(AddressMatch {
            address,
            name: name.to_string(),
        });
        if matches.len() >= limit {
            break;
        }
    }
    Ok(matches)
}

/// Search `ScriptString` entries by case-insensitive regex.
pub fn find_strings(
    script: &Value,
    pattern: &str,
    limit: usize,
) -> Result<Vec<StringLiteralMatch>, Error> {
    let regex = Regex::new(&format!("(?i:{pattern})"))?;
    let strings = script
        .get("ScriptString")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::InvalidMetadata("script.json has no ScriptString array".into()))?;
    let mut matches = Vec::new();
    for entry in strings {
        let Some(value) = entry.get("Value").and_then(Value::as_str) else {
            continue;
        };
        if !regex.is_match(value) {
            continue;
        }
        let Some(address) = json_u64(entry.get("Address")) else {
            continue;
        };
        matches.push(StringLiteralMatch {
            address,
            value: value.to_string(),
        });
        if matches.len() >= limit {
            break;
        }
    }
    Ok(matches)
}

fn read_text(path: &Path) -> Result<String, Error> {
    let bytes = fs::read(path).map_err(|source| io_error(path, source))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn parse_hex(value: &str) -> Result<u64, Error> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16)
        .map_err(|error| Error::InvalidHex(format!("{value:?}: {error}")))
}

fn json_u64(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::Number(number) => number
            .as_u64()
            .or_else(|| number.as_i64().map(|v| v as u64)),
        Value::String(string) => {
            let trimmed = string.trim();
            if let Some(hex) = trimmed.strip_prefix("0x") {
                u64::from_str_radix(hex, 16).ok()
            } else {
                trimmed.parse().ok()
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn query_script_entries() {
        let script = json!({
            "ScriptMethod": [
                {"Address": 4096, "Name": "Player.TakeDamage"},
                {"Address": "0x2000", "Name": "World.Load"}
            ],
            "ScriptString": [
                {"Address": 12288, "Value": "aniimo.com"},
                {"Address": 16384, "Value": "other"}
            ]
        });
        assert_eq!(
            find_addresses(&script, "damage", 20).unwrap()[0].address,
            4096
        );
        assert_eq!(
            find_strings(&script, r"aniimo\.com", 20).unwrap()[0].address,
            12288
        );
    }
}
