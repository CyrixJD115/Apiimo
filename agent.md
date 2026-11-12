# agent.md: Apiimo_src

Knowledge base and rules for the Aniimo analysis and protocol toolkit.
`spec.md` describes it, and `plan.md` is the roadmap.

## What this project is

A Rust toolkit (the `apiimo` CLI plus library crates). It:
- decrypts and rebuilds Aniimo's protected `global-metadata.dat` and runs
  Il2CppDumper
- answers class/method/string queries
- inspects the Lua pack (`LuaScripts.xdf`)
- implements the gate protocol from the client side

That last part is the reference client Serviimo tests against. AniiStudio
drives it through `ans-apiimo`. It's a byte-exact port of the original
Python tool.

Scope (AniiStudio `LEGAL.md` §4–6): your own legitimately obtained game
files, and **your own account only** for anything that touches a network.
`gate-probe`, `gate-status`, `save-pull`, `world-pull` and the
`apiimo-atlas` Homeland client must never be pointed at another person's
account or used to automate against the official service. New features go
toward Serviimo, not the live servers.

## Rules

1. **Keys are data.** Every keyed build has an entry in
   `apiimo-crypto/keys.toml` (`apiimo` semver, `manifest` as an unquoted
   integer, `date`, `note`, 1152-byte keystream). Adding a key needs no code
   change. Never delete an old key.
2. **A new build flows like this:**
   - `apiimo key` → embedded match, or statistical recovery
   - `apiimo dump --out ../.dump/V<n>`
   - if discovery fails: `APIIMO_DISCOVER_TRACE=1` shows which anchor
     drifted
   - bank the key with provenance (manifest id, sha512 prefixes)
3. **Discovery derives layout from the data.** The section layout is
   scrambled per build. Anchors are self-validating, and the heap start and
   generic-parameter extent are proven against `<Module>` and the
   container-declared count, not assumed. Any change to `discover.rs` must
   keep the old/new layouts identical on every banked build (V1, V2, V4, V5,
   V6). Run the harness approach used on 2026-11-12: build both versions
   against the decrypted files and diff the section tables.
4. **Vendored `.proto` files are stale.** The descriptors compiled into the
   game's `xlua.dll` are authoritative (newer fields, the `entityMessage2C`
   RPC). See `../Serviimo_src/docs/gate-method-ids-2026-11-12.md`.
5. **The client protocol code must stay the live-verified client.** Don't
   loosen it to suit a test server. Serviimo adapts to the client, never the
   reverse.
6. Never commit game-derived files (dumps, decrypted metadata, captures,
   keys of other people). Embedded keystreams are factual functional data
   and stay.

## Facts worth knowing

- Metadata is IL2CPP v31 behind a 256-byte scrambled header slot, XOR-ed with
  a repeating 1152-byte keystream aligned to file offset 0.
- **Heap rule:** the identifier heap starts at the stringLiteralData end
  **aligned up to 4**. V1–V5 happened to end at 3 mod 4, and V6 (2026-11-12)
  is the first build where that rule and the old "+1" rule disagree.
- **Generic parameters:** count = max(`genericParameterStart + type_argc`)
  over containers. The table ends where the last record is owned by the last
  container, and constraint refs fit exactly.
- **Wine/Proton:** NEP2 holds `global-metadata.dat` exclusively while the game
  runs. Analyze an offline copy (`../.Aniimo_Steam`, via `download_aniimo.sh`
  / DepotDownloader) or the Steam install with the game closed.
- **Dumper chain:** embedded Il2CppDumper bundle (`tools/embed-dumper.sh`),
  then `il2cpp-dumper` on PATH, or an explicit `--dumper`. It is extracted to
  `~/.cache/apiimo/dumper-<fnv>`.
- **REA + Ghidra** (`../tools/rea`) complement Apiimo for native work in
  `xlua.dll` / GameAssembly. REA's own IL2CPP binary linking is unreliable on
  these builds, so use Apiimo's `script.json` for addresses.

## Build and verify

```sh
cargo build --release            # target/release/apiimo
cargo test --workspace           # 91 tests on 2026-11-12
APIIMO_GAME=../.Aniimo_Steam target/release/apiimo key
APIIMO_GAME=../.Aniimo_Steam target/release/apiimo dump --out ../.dump/V<n>
```

## Working-tree state (2026-11-12)

`main` is 2 commits ahead of `origin/main` (gate session and world-pull,
rebased onto upstream). The uncommitted work includes:
- the discovery fixes (`apiimo-core/src/discover.rs`)
- the 0.3.2 key (`keys.toml`)
- network/api changes
- the untracked `apiimo-atlas/` crate

A backup is on branch `backup/wip-2026-11-12`.
