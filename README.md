# dae

[简体中文](README.zh.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/ejfkdev/dae)](https://github.com/ejfkdev/dae/releases/latest)
[![crates.io](https://img.shields.io/crates/v/dae-rs)](https://crates.io/crates/dae-rs)
[![Release CI](https://img.shields.io/github/actions/workflow/status/ejfkdev/dae/release.yml?label=build)](https://github.com/ejfkdev/dae/actions/workflows/release.yml)
[![Publish CI](https://img.shields.io/github/actions/workflow/status/ejfkdev/dae/publish.yml?label=publish)](https://github.com/ejfkdev/dae/actions/workflows/publish.yml)
[![Built with ZCode](https://img.shields.io/badge/Built%20with%20ZCode-000000.svg?style=flat&logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMTE4IiBoZWlnaHQ9IjEwMCIgdmlld0JveD0iMCAwIDI1NiAyMTgiPjxwYXRoIGZpbGw9IiNmZmZmZmYiIGQ9Ik0xMzQuNCAwLjEzMDE1MkwxMTEuNDggMjUuNjAyMkMxMTEuNjY1IDI5LjU2OTkgMTA5LjA1NCAzMi4wMDE5IDEwNC4wNjQgMzIuMDAxOUg2LjM5OTlWMEM2LjM5OTkgMC4xMzAxNDkgMTM0LjQgMC4xMzAxNTIgMTM0LjQgMC4xMzAxNTJaIi8+PHBhdGggZmlsbD0iI2ZmZmZmZiIgZD0iTTI1NiAwLjEzMDEyN0wxMDIuNDAxIDIxNy43MzJIMDBMMTUzLjU5OSAwLjEzMDEyN0gyNTZaIi8+PHBhdGggZmlsbD0iI2ZmZmZmZiIgZD0iTTEyMS42MDEgMjE3LjczMkwxMzkuNjUgMTkyLjEzNEMxNDIuNDY1IDE4OC4xNjYgMTQ3LjA3NiAxODUuNzM0IDE1Mi4wNjcgMTg1LjczNEgyNDkuNjA0VjIxNy43MzZIMTIxLjYwMVYyMTcuNzMyWiIvPjwvc3ZnPg==)](https://zcode.z.ai/)

> Config-driven **Dart AOT snapshot** debug-info exporter. No Dart SDK, never runs the target: locates the embedded snapshot inside Mach-O / ELF / PE and exports the same symbols and structs as [blutter](https://github.com/worawit/blutter).

Works on any Dart AOT artifact — Flutter release builds, `dart compile exe`, `dart compile aot-snapshot` (Dart 2.7+ cluster snapshots).

## Features

- **Self-contained & auto-detecting** — all 26 SDK profiles are embedded; the Dart version is matched by snapshot hash, with a structural-probe fallback for custom/Flutter-engine builds.
- **Fast** — a 24 MB Flutter sample exports in ~0.07 s (~27× the Python reference).
- **Bilingual CLI** — Chinese locale prints Chinese, everything else English; override with `DAE_LANG=zh|en`.
- **Zero dependencies** — parses Mach-O/ELF/PE directly.

## Install

| Way | Command |
|---|---|
| Homebrew (macOS) | `brew install ejfkdev/tap/dae` |
| cargo | `cargo install dae-rs` |
| Prebuilt | binary from [Releases](https://github.com/ejfkdev/dae/releases/latest) — Windows/macOS/Linux × x64/arm64 |
| Source | `cargo build --release` |

macOS prebuilt binaries are ad-hoc signed; if Gatekeeper blocks the first run: `xattr -dr com.apple.quarantine dae`.

*(The crates.io package is `dae-rs` because `dae` was taken; the repository, library and binary all stay `dae`.)*

## Usage

```bash
dae <binary> <out_dir>                    # auto-detect the Dart version
dae <binary> <out_dir> --sdk-profile P.json   # or force one
```

```console
$ dart compile exe demo.dart -o demo
$ dae demo out
SDK profile: dart/3.13.0 (version-hash match)
export done -> /absolute/path/to/out:
  ida_script/  r2_script/  frida.js  asm/
  text/  pp.txt · objs.txt · strings.txt · libs.txt · classes.txt · functions.txt · arrays.txt · maps.txt
```

- **IDA** — `File → Script file…`, pick `ida_script/addNames.py`. Names, boundaries and the `DartThread` / `DartObjectPool` structs land in the database (image base rebased automatically).
- **radare2** — `r2 -i r2_script/addNames.r2 <binary>`, then `to r2_dart_struct.h` in the session.
- **Frida** — edit the marked hook line, then `frida -f <app> -l out/frida.js`.

## Outputs

| Output | Purpose |
|---|---|
| `ida_script/addNames.py` | IDAPython: names + boundaries + structs |
| `r2_script/addNames.r2` | radare2 flags/comments (libraries → classes → methods) |
| `*_dart_struct.h` | Dart runtime structs (`r2_script/r2_dart_struct.h`, `ida_script/ida_dart_struct.h`) |
| `frida.js` | Frida template + runtime `Classes` array |
| `asm/*.dart` | disassembly with blutter-style IL comments (arm64) |
| `pp.txt` | object-pool entries (under `text/`) |
| `objs.txt` | recursive user-class instance dump (under `text/`) |
| `strings.txt` | full string table (under `text/`) |
| `libs.txt` | library inventory (URI + name, under `text/`) |
| `classes.txt` | class inventory (ref, cid, library, name; under `text/`) |
| `functions.txt` | flat `Library.Class.method → offset` index (under `text/`) |
| `arrays.txt` / `maps.txt` | every List / Map object with its contents (under `text/`) |
| `text/call_edges.txt` | call edges: direct `bl`/`call` targets + indirect call sites; per-class allocation stubs are named from their prologue |
| `callgraph.dot` | direct-call graph between named functions (Graphviz DOT) |
| `dart/*.dart` | per-function pseudocode, with `--decompile` (experimental) |

Struct headers are generated **per target**: `DartThread` from a version × architecture layout table, `DartObjectPool` from the target's own object pool.

## Dart version support

| Range | Status |
|---|---|
| 3.0.0 – 3.14β | ✅ verified — full user functions |
| 2.15.0 – 2.17.0 | ✅ verified — full user functions |
| 2.10.4 – 2.14.4 | function names + addresses |
| 2.7.2 | objects layer only |
| 1.24.3 / 2.0.0 | ❌ JIT snapshot (non-AOT) |

## Tool compatibility

| Tool | Status |
|---|---|
| IDA 9.3 / 9.4 | ✅ tested end-to-end (naming + structs) |
| IDA 7.x – 8.x | expected — same typed APIs since 7.x |
| radare2 6.2 | ✅ tested — no script errors |
| radare2 5.x | expected — long-stable commands only |
| rizin | parses/executes; one-flag-per-address skips same-address extras |
| Frida 14 – 17 | core `Interceptor`/`Module`/`ptr` API |

## How it works

Three layers; the engine is version-invariant, versions add configuration only:

| Layer | Path | Contents |
|---|---|---|
| Engine | `src/` | varint/cluster traversal, fill interpreter, name deobfuscation, exporters |
| SDK profile | `profiles/sdk/*.json` | cid enums, field layouts (fill DSL), tagging, offsets |
| Platform profile | `profiles/platform/*.json` | container parser, symbol names, register roles |

Spec: [`docs/PROFILES.md`](docs/PROFILES.md)

## Decompiler (experimental)

`dae --decompile` adds `dart/<library>.dart`: one pseudocode function per named function,
lifted from the disassembly through the same pipeline shape the sibling tools use
(machine-specific lift → basic blocks → emission).

What it does today: real comparison conditions folded from `cmp`/`test` + the branch
(`if (rdx < 2)`), framework register names (`PP`/`THR`/`SP`/`FP`) including inside memory
operands, named direct call targets, and the raw disassembly kept as a comment block above
each function so the output stays checkable.

Control flow is **structured**: dominators give the natural loops (back edge = header
dominates its tail), then each region is emitted recursively — a conditional branch whose
two arms rejoin becomes `if/else`, a loop header becomes `while`, and an arm that leaves the
loop becomes `break`/`continue`. Roughly 60% of functions come out fully structured; the
rest keep a `goto` and are marked with a `NOTE` header so a reader knows which files are
pseudocode rather than Dart.

What it does **not** do yet: expression nesting (`mem(qword ptr [FP + 8])` stays flat rather
than composing into field reads), and type recovery. Unrecognised instructions are emitted
verbatim as `// unmapped:` rather than approximated.

A shape gate runs on every change (`tests/decompiler_shape.rs`): braces must balance in every
emitted file — an unbalanced file means a branch was silently dropped — every in-function
statement must terminate, and the structured rate has a floor.

## Known limitations

- Addresses are file-offset space, not runtime VAs (matches the blutter reference)
- `asm/` IL comments are arm64-only (x64 disassembly is emitted)
- Call graph: indirect calls (`blr` / `call reg`) stay unresolved by design — their targets
  are computed at runtime. Direct targets land on a name when the target is an exported
  function or a per-class allocation stub (recognised from the stub prologue, which
  materialises the class id); anything else keeps its address and an empty name. On
  2.16.x the class layer itself is not parsed yet, so stub naming is skipped there
  (reported as coverage, never as a guessed name).
- PE stripped of COFF symbols needs a `.pdb` backfill first
- Dart 1.24 / 2.0 are JIT snapshots and unsupported

## License

[MIT](LICENSE)