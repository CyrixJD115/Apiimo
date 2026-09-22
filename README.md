# Apiimo

Apiimo is a Rust workspace for the Aniimo metadata and binary-analysis
toolkit. It is a verified port of the original Python implementation
(kept for reference under `Apiimo_py/`): running the full dump pipeline
with the Rust `apiimo` binary reproduces the Python tool's
`global-metadata.decrypted.dat` and `dump.cs` byte for byte, in about a
third of the time.

## Workspace

| Crate | Scope |
|---|---|
| `apiimo-crypto` | The embedded 1152-byte repeating-XOR keystream, body decryption, and the statistical key-recovery fallback for new builds. No I/O; pure buffer routines. |
| `apiimo-core` | The hub: metadata rebuilding (vanilla v31 header + verified section layout), default-value sanitization, PE VA/file-offset helpers, binary patching, dump orchestration, and post-dump queries. Routes its crypto needs through `apiimo-crypto`. |
| `apiimo-network` | The decoded gate/login protocol: vendored `phonest.proto` schemas, protobuf wire codec, MsRequest RPC envelope (msgpack/base64), gate handshake types, credential parsers, endpoint registry, and XDF/LuaJIT tooling (`apiimo xdf` / `lua-strings` / `xdf-cat`). |
| `apiimo-api` | The boundary layer: the `apiimo` CLI binary plus a library API (`Command`/`Output` enums, serde-serializable) for AniiStudio to drive through `ans-apiimo`. |

Layering: `apiimo-api` -> `apiimo-core` -> `apiimo-crypto`, with
`apiimo-network` beside the api facade for future server-side work.

## CLI

```
apiimo [--game <dir>] [--out <dir>] [--json] <command> [args]

  dump                        full pipeline -> <out> (default: <game>/.dump)
  classes <regex>             list matching classes
  methods <regex>             list matching methods with VA
  fields <ClassRegex>         dump a class layout (fields + offsets)
  addr <SubStr>               resolve method addresses from script.json
  str <regex>                 search string literals
  va2off <va_hex>             GameAssembly.dll VA -> file offset
  off2va <off_hex>            file offset -> VA
  patch <va_hex> <hexbytes>   patch GameAssembly.dll in place
  discover                    experimental: rediscover section layout
```

`--game` defaults to the `APIIMO_GAME` environment variable, then an
upward walk looking for `GameAssembly.dll` / `Aniimo_Data`. `--json`
prints the structured result instead of the human rendering — the shape
AniiStudio consumes.

The external `il2cpp-dumper` executable remains an explicit runtime
dependency of the dump pipeline, just as in the Python tool.

## Embedded dumper (`apiimo-il2cpp/` submodule)

The repo pins [c01ns/Il2CppDumper](https://github.com/c01ns/Il2CppDumper)
as a git submodule at `apiimo-il2cpp` — a fork with experimental support
for newer Unity 6000.x metadata versions (v35/v38/v39) alongside the v31
that Aniimo uses. The dumper can be **compiled into the `apiimo` binary
itself**, making it fully self-contained (no dotnet, no PATH dumper
needed at runtime):

```bash
git clone --recurse-submodules <this repo>
tools/embed-dumper.sh        # dotnet publish (self-contained single-file) + zstd
cargo build --release
```

The script publishes the dumper as a self-contained single-file
executable, compresses it (zstd, ~24 MB) into
`apiimo-api/assets/il2cpp-dumper.sfx.zst`, and `include_bytes!` embeds it
at compile time. `cargo build` still works without running the script —
the assets are placeholders and the binary simply uses the PATH
fallback.

At dump time the embedded bundle is extracted once into the Apiimo cache
(`$XDG_CACHE_HOME/apiimo` or `~/.cache/apiimo`) under a directory named
after the bundle's FNV-1a-64 hash, so unchanged builds never rewrite
disk, and stale entries from older builds are garbage-collected. The
dumper chain is:

1. **embedded** bundle (extracted on demand), then
2. **`il2cpp-dumper` on PATH** if extraction or execution fails.

An explicit `--dumper <path>` (a native executable or a `.dll`, which is
run through `dotnet`) bypasses the chain entirely. `DumpReport`
records which dumper ran in `dumper_command`, so upstream callers
(AniiStudio / `ans-apiimo`) always see the same report shape.

## Session-pull research (`apiimo-network`)

The recovered login architecture (from the dump + the shipping, unencrypted
`LuaScripts.xdf` container of LuaJIT bytecode):

```
Steam -> FPX SDK (native) -> FPCUser/credentials (fpId, accountId,
         ticket, sessionKey)
      -> LoginAgent.lua verifies sdkinfo against the login service
      -> server selection (cached per-accountId)
      -> GateClient: KCP primary / ws://{host}:{port} fallback, token
         + sessionId handshake (GlobalGateSessionId)
      -> roleInfo.players -> select role -> LoginLoadWorld
      -> the "save" materializes as server-side world state via ECS sync
```

The `xdf` / `lua-strings` commands make the Lua protocol layer inspectable
offline. A live login (2026-09-21) then confirmed the whole chain from the
game's own logs (`fpxui.log` + the `PHONESTCORE_HOOK` lines in
`Player.log`): Steam ticket -> FPX session_key/ticket -> login service ->
KCP gate (`worldx-us-prod-singleworld-1000-gate...:20000`) with an
encrypt-key-confirmation handshake, while per-player blobs (client info,
pet data) sync to Aliyun OSS under presigned URLs. The registry now
carries the gates, OSS buckets, payment services, and the public
`server_list_publish.json` CDN; `ServerListPublish` parses that document,
and `FpxTicket`/`FpxSessionKey`/`LiveIdentity` decode the observed
credential structures (including the roleId "Class" prefix encoding).

## Protocol layer (`apiimo-network`)

The gate protocol is fully decoded and implemented as library types —
the game's own `.proto` schemas are vendored under `apiimo-network/proto/`
(extracted verbatim from `LuaScripts.xdf`, package `phonest.proto`):

- `pb` — minimal protobuf wire codec (varint/bytes/nested, tolerant decode)
- `handshake` — EncryptToken/EncryptKey/ConnectServerReq/Resp/Heartbeat
- `rpc` — MsRequest/MsResponse (protocol 33), the `POST /rpc` JSON
  envelope with base64-msgpack params, and the known service-method
  registry (`LoginService.verifySdk`, `RoleService.CS_Login`,
  `KvService.kvServiceFind`, ...)
- `identity` — FpxTicket/FpxSessionKey parsers and the
  `VerifySdkRequest/Response`, `CsLoginRequest/CsLogoutRequest` contracts

A full login replay additionally needs the gate TCP framing and the RSA
public key source (see `tools/lua-disasm/` for the disassembly toolchain
used to recover all of this).

## Library use

```rust
use apiimo_api::{Apiimo, Command};

let mut apiimo = Apiimo::with_game_dir("/path/to/Aniimo");
match apiimo.run(&Command::classes("AntiCheat"))? {
    apiimo_api::Output::Classes(matches) => { /* structured matches */ }
    _ => unreachable!(),
}
```

## Build and test

```bash
cargo test --workspace
```
