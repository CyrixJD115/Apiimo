# plan.md: Apiimo_src

Written 2026-11-12. Apiimo is the update engine for the whole ecosystem.
Every game patch passes through it before the loader or Serviimo can follow.

## A0: hygiene

1. Commit the WIP in reviewable pieces:
   - discovery fixes and tests
   - the 0.3.2 key
   - network/api changes
   - `apiimo-atlas`

   Push `main` (currently 2 ahead). *Accept:* clean tree, 91+ tests green.
2. Bump the workspace version to 0.3.2. `Cargo.toml` still says 0.3.0 while
   `keys.toml` banks keys as 0.3.1 and 0.3.2.
3. Bump AniiStudio's `modules/Apiimo` pin afterwards.

## A1: key banking as a command

`apiimo key --bank` appends a correctly formatted `keys.toml` entry: manifest
read from `.DepotDownloader`, sha512 prefixes of GameAssembly and metadata,
type and assembly counts from a successful dump. It refuses to bank a key
whose dump failed. *Accept:* the next update is banked without hand-editing
TOML.

## A2: protos from the shipping client

`apiimo protodesc <xlua.dll> --out <dir>` finds every embedded
FileDescriptorProto (`client_gate.proto`, `common.proto`, …) and emits
`.proto` text. Replace the vendored copies under `apiimo-network/proto/`,
then fix any codec that differed: `EncryptKey` padding,
`PropertyStrategySync`, `PropertyIdSync.value`, sessionId fields. *Accept:*
regenerating from the 2026-11-12 `xlua.dll` reproduces the fields Serviimo
already decodes. Prototype parsers are in `../tools/protodesc/`
(`client_gate_services.py`, `messages.py`), which were used to recover the
2026-11-12 tables.

## A3: discovery regression corpus

Keep a local (git-ignored) corpus of the decrypted V1, V2, V4, V5 and V6
buffers. Add an ignored test (`APIIMO_CORPUS=<dir> cargo test -- --ignored`)
that asserts the stored section tables for each. This turns the 2026-11-12
old-vs-new comparison into a permanent gate. *Accept:* a CI-runnable check
when the corpus is present.

## A4: update pipeline entry point

One `apiimo update --game <dir>` that:
- detects a new build (manifest or sha)
- runs `key`, then recovery and banking if needed
- runs `dump`
- writes a machine-readable report for AniiStudio and the loader's
  `regen.py`

*Accept:* used as the first stage of the AniiModLoader P4 update command.

## A5: client protocol completeness (serves Serviimo)

- Add `recvHeartbeat` handling and gate→client id constants to
  `LiveSession` (it only checks 10/11/19 today).
- Add a decoder for the lazy entity format, mirroring
  `serviimo-world::lazy_value`, so `world-pull` captures of your own session
  can be decoded offline.

## A6: Windows

Build `apiimo.exe` (`x86_64-pc-windows-gnu`) and verify the embedded dumper
path on Windows. Low priority while Linux is the main platform.
