# Apiimo

Reverse-engineering toolkit for **Aniimo** (FunPlus / Polaris Quest,
Unity 2022.3.62f1, IL2CPP metadata v31).

The game ships a fully-encrypted `global-metadata.dat` (custom 1152-byte
repeating-XOR keystream over the whole file, reordered metadata sections,
and a non-standard header). The stock Il2CppDumper rejects it. Apiimo
undoes all of that and produces a complete, zero-error dump.

## Quick start

```bash
cd Apiimo
python3 apiimo.py dump                 # full pipeline -> ../.dump
python3 apiimo.py classes "Player"     # find classes
python3 apiimo.py methods "TakeDamage" # find methods + VA
python3 apiimo.py fields "XSwitchConfig"
python3 apiimo.py addr "DebugConsole"  # addresses from script.json
python3 apiimo.py str "aniimo.com"     # search string literals
```

## How the decryption works

1. The whole metadata file is XOR'd with a 1152-byte keystream
   (embedded in `EMBEDDED_KEY_HEX`, recovered statistically from the
   plaintext structure of the embedded C# string tables).
2. Metadata sections are laid out in a **custom order** (not the vanilla
   v31 order), and the original header's first 31 fields are garbage.
   Apiimo locates every section by structure (token grids:
   `0x06`=methods, `0x08`=params, `0x04`=fields, `0x02`=typedefs,
   `0x14`=events, `0x17`=properties; literal-table chain constraints;
   column-sanity scans) and writes a fresh **vanilla** header instead.
3. The protector adds bogus `fieldDefaultValues` / `parameterDefaultValues`
   records (type handles the vanilla dumper can't resolve, `dataIndex = -1`).
   These are sanitized to a benign primitive + null blob offset so no image
   is lost to exceptions.

## Commands

| Command | Description |
|---|---|
| `dump` | decrypt + rebuild + sanitize + run Il2CppDumper |
| `classes <regex>` | search class/struct/interface names |
| `methods <regex>` | search method signatures with RVA/VA |
| `fields <ClassRegex>` | print a class layout (fields + offsets) |
| `addr <substr>` | resolve method addresses from `script.json` |
| `str <regex>` | search the 45,240 string literals |
| `va2off <va>` / `off2va <off>` | GameAssembly.dll VA <-> file offset |
| `patch <va> <hexbytes>` | patch bytes into GameAssembly.dll |
| `discover` | experimental dynamic section rediscovery |

Global options: `--out <dir>` (default `<game>/.dump`), `--game <dir>`.

## Injection workflow (typical)

1. `python3 apiimo.py dump`
2. Load `GameAssembly.dll` in IDA/Ghidra, apply `script.json`
   (Il2CppDumper plugin) and `il2cpp.h` for full symbols.
3. Find your target: `python3 apiimo.py methods "PlayerController"`.
4. The dump prints `RVA / Offset / VA` per method — use `va2off` to convert
   a VA to a raw file offset for `patch`, or hook at runtime with the VA.

## Status

- 28,348 / 28,348 types, 133 images, 0 dumper errors
- 392,378 methods in `script.json`, 45,240 string literals
- 134 dummy assemblies
