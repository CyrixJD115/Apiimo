# spec.md: Apiimo_src

## Purpose

Turn a legitimately owned Aniimo install into analyzable data: decrypted
metadata, a dump (`dump.cs`, `script.json`, `il2cpp.h`, DummyDlls), queries,
Lua-pack inspection. Also provide the reference client-side implementation of
the gate protocol. It's consumed by people (CLI), by AniiStudio (library,
JSON), by Serviimo (path dependency on `apiimo-network`), and by
AniiModLoader (metadata code lifted into `aniimod-metadata`).

## Crates

| crate | scope |
|---|---|
| `apiimo-crypto` | Embedded keystore (`keys.toml`, one `[[build]]` per keyed build), XOR body decryption, key selection by printable-rate, statistical recovery plus refinement for unknown builds. Pure buffers, no I/O. |
| `apiimo-core` | Section discovery (`discover.rs`, opt-in trace), metadata rebuild to a vanilla v31 header, default-value sanitization, PE VA↔offset, patching, dump orchestration, queries over the dump |
| `apiimo-network` | Vendored `phonest.proto` schemas, protobuf codec, RC4, handshake types, continuous RC4+zlib `LiveSession`, MsRequest/MsResponse + msgpack params, login chain (`verifySdk`, `CS_Login`, `bind`, world `connectServer`), FPX credential parsers, endpoint registry, XDF/LuaJIT tooling |
| `apiimo-api` | `apiimo` CLI and serde `Command`/`Output` library API (`--json` output is the AniiStudio contract) |
| `apiimo-atlas` | Async client for the game-side Homeland bridge: a loopback WebSocket JSON-RPC (`ws://127.0.0.1:<port>/`). Position-only, owner-verified mutations, journalled before dispatch, never auto-retried. Port of the SwiftUI app's `HomelandCommandClient`. |
| `apiimo-il2cpp` (submodule) | Il2CppDumper fork, optionally embedded into the binary |

Layering: `apiimo-api` → `apiimo-core` → `apiimo-crypto`; `apiimo-network`
and `apiimo-atlas` sit beside the API.

## CLI

`--game` defaults to `$APIIMO_GAME`, then an upward search. `--json` gives a
structured result.

| group | commands |
|---|---|
| Metadata | `dump`, `key [file] [out] [--recover]`, `discover` |
| Queries | `classes`, `methods`, `fields`, `addr`, `str` |
| Binary | `va2off`, `off2va`, `patch` (writes the target file; only on analysis copies) |
| Lua pack | `xdf`, `lua-strings`, `xdf-cat` |
| Network | `gate-probe`, `gate-handshake`, `gate-status`, `save-pull`, `gate-decrypt`, `world-pull`. Own account only. |

## Key contracts

- **Dump outputs:** `global-metadata.decrypted.dat` (rebuilt),
  `dump.cs`, `script.json`, `il2cpp.h`, `stringliteral.json`, `DummyDll/`.
  `DumpReport` records which dumper ran.
- **Keystore entry:**
  `{apiimo = "x.y.z", manifest = <int>, date, note, key = '''<2304 hex>'''}`.
- **Gate wire:** `[u32 LE len][u16 LE method][protobuf]`. Ids per
  `../Serviimo_src/serviimo-gate/src/methods.rs`.

## Banked builds (as of 2026-11-12)

| apiimo | build | note |
|---|---|---|
| 0.1.0 | launch build, 2026-09-17 (manifest 2614998) | statistical recovery |
| 0.2.0 | first update, 2026-09-22 (manifest 3584014) | refined statistical pass |
| 0.3.0 | V4, 2026-09-30 (manifest 8275010856276034521) | |
| 0.3.1 | 2026-10-01 GameAssembly | recovered 2026-10-10 |
| 0.3.2 | 2026-11-12 (manifest 6655971786467105815) | 29,155 types / 136 assemblies |

## Platform

Built and run on Linux, on an offline copy of the game files. Windows builds
should work (pure Rust, plus the dumper as an `.exe` or through dotnet) but
are untested.
