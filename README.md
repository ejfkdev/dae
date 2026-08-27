# dae

[简体中文](README.zh.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/ejfkdev/dae)](https://github.com/ejfkdev/dae/releases/latest)
[![crates.io](https://img.shields.io/crates/v/dae-rs)](https://crates.io/crates/dae-rs)
[![Release CI](https://img.shields.io/github/actions/workflow/status/ejfkdev/dae/release.yml?label=release%20build)](https://github.com/ejfkdev/dae/actions/workflows/release.yml)

Config-driven Dart AOT snapshot debug-info exporter (Rust). Zero Dart SDK dependency, never runs the target. Locates the snapshot inside Mach-O / ELF / PE binaries and exports the same debug data as [blutter](https://github.com/worawit/blutter).

**Works with every Dart AOT artifact**: Flutter release builds (iOS/Android/macOS/Windows/Linux), `dart compile exe`, `dart compile aot-snapshot` — as long as the binary embeds a Dart 2.7+ cluster snapshot, no framework assumptions.

- Function name ↔ address (library::class::method hierarchy, obfuscated-name recovery)
- Object pool entries (`pp.txt`), recursive user-class instance dump (`objs.txt`)
- radare2 naming script (`r2_script/addNames.r2` + `r2_dart_struct.h`)
- Frida runtime Classes array (`blutter_frida.js`)
- capstone disassembly + IL pseudo-instruction comments (`asm/`, arm64)

## Install

### Prebuilt releases

Download the binary for your platform (Windows/macOS/Linux × x64/arm64; x64 binaries are UPX-compressed) from [GitHub Releases](https://github.com/ejfkdev/dae/releases/latest) and run it directly.

macOS binaries are ad-hoc signed. If Gatekeeper blocks the first run, clear the quarantine attribute:

```bash
xattr -dr com.apple.quarantine dae
```

### cargo

```bash
cargo install dae-rs                                # from crates.io (after first publish)
cargo install --git https://github.com/ejfkdev/dae  # straight from this repository
```

Both install a command named `dae`. The crates.io package is `dae-rs` because the name `dae` was already taken; the repository, library, and binary all remain `dae`. From a local checkout you can also `cargo install --path .`.

### Homebrew (macOS)

```bash
brew install ejfkdev/tap/dae
```

### Build from source

```bash
cargo build --release
```

## Quick start

```bash
dae <binary> <out_dir> [--sdk-profile <profile.json>]
```

All 26 SDK profiles and the platform profiles are **embedded in the binary**; no profile files are needed at runtime. The Dart version is detected automatically — by snapshot version-hash match for official SDK builds (`version_hashes.json`), with a structural probe (alloc + fill scoring) as fallback for custom/Flutter engine builds. `--sdk-profile` / `--platform-profile` are only overrides for unusual targets.

## Version support

`profiles/sdk/` embeds **26 Dart versions** (1.24.3 → 3.14β), covering the full cluster-snapshot format lineage.

| Version range | Status | Notes |
|---|---|---|
| 1.24.3 / 2.0.0 | unsupported | JIT snapshot format, not AOT |
| 2.7.2 | objects layer | ≤2.9 has no instruction table; object layer only |
| 2.10.4–2.14.4 | address layer | function names + addresses exported |
| 2.15.0–2.17.0 | verified | complete user functions |
| 2.16.2 / 2.18.1 / 2.19.6 | ELF backfill | function names backfilled from ELF symbols |
| 3.0.0–3.14β | verified | complete user functions |

**21 unit tests** (`cargo test`) all green. No known 2.x/3.x gaps.

## Architecture

Three layers; the engine never changes, only configuration is added:

| Layer | Path | Contents | Changes when |
|---|---|---|---|
| Engine | `src/` | three varint encodings for the datastream, cluster stream traversal, fill interpreter, name deobfuscation, export writers | never |
| SDK profile | `profiles/sdk/*.json` | cid enums, cluster field layouts (fill DSL), tagging, runtime offsets | per Dart version |
| Platform profile | `profiles/platform/*.json` | container parser, symbol names, register roles | per (container × arch) |

Spec: [`docs/PROFILES.md`](docs/PROFILES.md) (Chinese)

## Performance

macOS Flutter sample (24 MB binary → 14 MB of artifacts): **0.07 s wall-clock** (Python reference implementation: 1.9 s, ~27×). 8-core parallel processing (mimalloc allocator, chunked parallelism, compiled fill interpreter).

## Known limitations

- Addresses are in file-offset space (not runtime VAs), matching the blutter reference implementation
- asm IL currently covers arm64 only; x64 disassembly is emitted but IL comments are pending
- PE binaries stripped of the COFF symbol table need symbols backfilled from a .pdb first
- 1.24 / 2.0 are JIT snapshots (`kMessageMagic`), unsupported

## License

[MIT](LICENSE) · third-party notices: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)