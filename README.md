# Apiimo

Apiimo is a Rust workspace for the Aniimo metadata and binary-analysis
toolkit. It ports the core behavior of the original Python implementation
while keeping networking and API integrations isolated for later work.

## Workspace

| Crate | Scope |
|---|---|
| `apiimo-core` | Metadata rebuilding, default-value sanitization, PE VA/file-offset helpers, binary patching, dump orchestration, and post-dump queries |
| `apiimo-crypto` | Aniimo's embedded 1152-byte repeating-XOR keystream, body decryption, and statistical key recovery |
| `apiimo-network` | Scaffold only |
| `apiimo-api` | Scaffold only |

## Build and test

```bash
cargo test --workspace
```

The core pipeline is library-first. A caller can run the full dump flow with
`apiimo_core::run_dump`, or use the lower-level functions independently:

```rust
use apiimo_core::{run_dump, DumpOptions};

let report = run_dump(&DumpOptions::new("/path/to/Aniimo"))?;
assert!(report.dumper_succeeded);
```

The external `il2cpp-dumper` executable remains an explicit runtime
dependency of the dump orchestration, just as it was in the Python tool.
