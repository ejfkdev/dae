# dae

[简体中文](README.zh.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/ejfkdev/dae)](https://github.com/ejfkdev/dae/releases/latest)
[![crates.io](https://img.shields.io/crates/v/dae-rs)](https://crates.io/crates/dae-rs)
[![Release CI](https://img.shields.io/github/actions/workflow/status/ejfkdev/dae/release.yml?label=release%20build)](https://github.com/ejfkdev/dae/actions/workflows/release.yml)

> Config-driven Dart AOT snapshot debug-info exporter. Zero Dart SDK dependency, never runs the target binary: it locates the snapshot inside Mach-O / ELF / PE files and exports the same debug data as [blutter](https://github.com/worawit/blutter).

**Works with every Dart AOT artifact** — Flutter release builds (iOS/Android/macOS/Windows/Linux), `dart compile exe`, `dart compile aot-snapshot` — as long as the binary embeds a Dart 2.7+ cluster snapshot.

- **No setup, self-detecting**: all 26 SDK profiles are embedded in the binary; the Dart version is detected automatically (snapshot version-hash match, with a structural probe fallback for custom/Flutter-engine builds)
- **Fast**: a 24 MB Flutter sample exports in ~0.07 s wall-clock (≈27× the Python reference implementation)
- **Bilingual CLI**: output follows the system locale — Chinese locales (Simplified/Traditional) print Chinese, everything else prints English; force with `DAE_LANG=zh|en`
- **Zero-framework**: parses the container formats directly, no Dart SDK or Flutter toolchain required

## Installation

### Prebuilt binaries

Download your platform binary (Windows/macOS/Linux × x64/arm64; x64 builds are UPX-compressed) from [GitHub Releases](https://github.com/ejfkdev/dae/releases/latest).

macOS binaries are ad-hoc signed; if Gatekeeper blocks the first run:

```bash
xattr -dr com.apple.quarantine dae
```

### Homebrew (macOS)

```bash
brew install ejfkdev/tap/dae
```

### cargo

```bash
cargo install dae-rs                                # from crates.io (after first publish)
cargo install --git https://github.com/ejfkdev/dae  # or straight from this repository
```

Both install a command named `dae`. (The crates.io package is `dae-rs` because the name `dae` was taken; the repository, library and binary all stay `dae`.)

### Build from source

```bash
cargo build --release
```

## Usage

```bash
dae <binary> <out_dir> [--sdk-profile <profile.json>]
```

Example — compile a tiny Dart program and export it:

```bash
$ dart compile exe demo.dart -o demo
$ dae demo out
SDK Profile: dart/3.13.0（version-hash match）
导出完成 → out:
  r2_script/addNames.r2     5 个函数名/地址
  ida_script/addNames.py    1175 个函数命名 + Dart 结构头
  blutter_frida.js          617 个 Classes 条目
  asm/                      5 个函数反汇编 + IL
  pp.txt                    1424 个对象池条目
  objs.txt                  17 个用户类实例
```

Import into IDA: `File → Script file…` and pick `ida_script/addNames.py` — function names, boundaries and the `DartThread` / `DartObjectPool` structs land in the current database (image-base rebasing is handled automatically). For radare2: `r2 -i r2_script/addNames.r2 <binary>`, then `to r2_dart_struct.h` to load the struct header.

## What it exports

| Output | Purpose |
|---|---|
| `ida_script/addNames.py` | IDAPython script: function names + boundaries, Dart structs |
| `r2_script/addNames.r2` | radare2 flag/comment script (libraries → classes → methods) |
| `r2_script/r2_dart_struct.h` | Dart struct layouts (also `ida_script/ida_dart_struct.h` for IDA) |
| `blutter_frida.js` | Frida template with the runtime Classes array |
| `asm/` | capstone disassembly + blutter-style IL comments (arm64) |
| `pp.txt` / `objs.txt` | object-pool entries / recursive user-class instance dump |

## Using the outputs

### IDA

1. Open the binary in IDA and let the initial auto-analysis finish.
2. `File → Script file…` and select `ida_script/addNames.py` — function names and boundaries are applied to the current database, and the `DartThread` / `DartObjectPool` structs are parsed in (the script auto-rebases to the image base).
3. Verify: jump to an address printed in the script (or any renamed function); the structs appear under `View → Open subviews → Structures`.

### radare2

```bash
r2 -i out/r2_script/addNames.r2 <binary>      # libraries/classes/methods become flags
# inside the session:
to out/r2_script/r2_dart_struct.h             # load the Dart struct header
f~method.                                     # browse the flags
```

### Frida

`blutter_frida.js` is a **template**: replace the marked hook line/address with an entry point you want to hook (pick one from the named functions), then:

```bash
frida -f <app> -l out/blutter_frida.js
```

The `Classes` array exposes per-class metadata (field bitmaps, sizes, argument offsets) for building hooks.

### Text outputs

- `asm/*.dart` — per-library disassembly with blutter-style IL pseudo-instruction comments; plain text, read directly or search.
- `pp.txt` — object-pool entries (immediates, object references, native/stub entries); useful for finding embedded data and constants.
- `objs.txt` — recursive dump of user-class instances (super chains, bool/List/Map contents); useful for recovering runtime object values.

## Dart version support

| Version range | Status |
|---|---|
| 3.0.0 – 3.14β | ✅ verified — full user functions |
| 2.15.0 – 2.17.0 | ✅ verified — full user functions |
| 2.10.4 – 2.14.4 | function names + addresses |
| 2.7.2 | objects layer only |
| 1.24.3 / 2.0.0 | ❌ JIT snapshot format (non-AOT) |

## Tool compatibility

| Tool | Status |
|---|---|
| IDA 9.3 / 9.4 | ✅ tested end-to-end (naming + structs) |
| IDA 8.x | expected — same typed APIs exist since 7.x (not run locally) |
| radare2 6.2 | ✅ tested — zero script errors, flags and comments land |
| radare2 5.x | expected — only long-stable commands are used |
| rizin | script parses/executes; its one-flag-per-address model skips auxiliary same-address flags (documented as-is) |
| Frida 14 – 17 | core-API surface (`Interceptor`/`Module`/`ptr`); runtime hooking to verify on your target |

## How it works

Three layers; the engine never changes between versions, only configuration is added:

| Layer | Path | Contents |
|---|---|---|
| Engine | `src/` | varint encodings, cluster-stream traversal, fill interpreter, name deobfuscation, export writers |
| SDK profile | `profiles/sdk/*.json` | cid enums, cluster field layouts (fill DSL), tagging, runtime offsets — one per Dart version |
| Platform profile | `profiles/platform/*.json` | container parser, symbol names, register roles — one per (container × arch) |

Spec: [`docs/PROFILES.md`](docs/PROFILES.md) (Chinese)

## Known limitations

- Addresses are in file-offset space (not runtime VAs), matching the blutter reference
- `asm/` IL comments cover arm64 only; x64 disassembly is emitted but IL comments are pending
- PE binaries stripped of the COFF symbol table need symbols backfilled from a .pdb first
- Dart 1.24 / 2.0 are JIT snapshots (`kMessageMagic`) and unsupported

## License

[MIT](LICENSE) · third-party notices: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)