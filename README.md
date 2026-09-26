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
- **Progressive mode** — `dae libs` / `classes` / `functions` / `strings` / `callers` to query the
  snapshot like a database, then `dae getclass` / `getmethod` / `getlib` to decompile just that
  one thing (`dae info` 0.03 s vs 1.9 s for a full export). See [Progressive mode](#progressive-mode-list-first-decompile-one-thing).
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
dae help                                  # progressive subcommands (list, then decompile one)
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
| `text/fields.txt` | named fields recovered from the snapshot's Field cluster (`rec`) or implicit-accessor names (`accessor`), with byte offsets |
| `text/call_edges.txt` | call edges: direct `bl`/`call` targets + indirect call sites; per-class allocation stubs are named from their prologue |
| `callgraph.dot` | direct-call graph between named functions (Graphviz DOT) |
| `dart/*.dart` | per-function pseudocode that passes `dart analyze` (with `--decompile`) |

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

Spec: [`docs/PROFILES.md`](docs/PROFILES.md) · Decompiler baseline: [`docs/DECOMPILER.md`](docs/DECOMPILER.md) · Measured against aotopsy: [`docs/COMPARISON.md`](docs/COMPARISON.md)

## Progressive mode (list first, decompile one thing)

A full export writes thousands of files; often you only want one class or one package.
Query first, decompile surgically (`dae help` has every option):

```
dae info      <binary>                        snapshot, SDK, sizes -- writes nothing
dae libs      <binary> [pattern]              libraries (packages) with class/function counts
dae classes   <binary> [pattern] [--lib P]    classes
dae functions <binary> [pattern] [--lib P]    functions (entry, size, owner)
dae strings   <binary> [-f TEXT]              snapshot string table
dae fields    <binary> [pattern]              named fields (source + byte offset)
dae largest   <binary> [-n N]                 biggest functions by code size
dae callers   <binary> <NAME|0xADDR>          who calls it (static direct-call edges)
dae disasm    <binary> <CLASS[.method]>       raw disassembly (arm64 keeps the IL comments)
dae getclass  <binary> <CLASS>                decompile just this class
dae getmethod <binary> <CLASS.method>         decompile just this method
dae getlib    <binary> <LIB>                  decompile just this library (package)
```

Conventions, chosen so the commands compose:

- **stdout is the data channel.** Query results and `get*` pseudocode go to stdout with no
  stats or timing mixed in; every diagnostic (target, SDK profile, warnings, counts) goes to
  stderr, so `dae getclass app.apk Foo | less` and `dae classes app.apk > index.tsv` just work.
  `-o FILE` writes to a file instead; `get*` with `-o FILE.dart` merges into one file and
  `-o DIR` writes the same `<DIR>/dart/<lib>.dart` layout as a full export.
- **Names you can guess.** A library can be written three ways — the `lib` column of
  `functions.txt` (`testing_app$screens$home`), the URL from `libs.txt`
  (`package:testing_app/screens/home.dart`), or the artifact file name
  (`testing_app_screens_home`) — and library names match by **prefix**, so
  `getlib testing_app` is the whole package. Classes are exact (case-insensitive fallback);
  add `--fuzzy` for substring. Functions accept `Class.method`, a bare member, or the
  artifact-style `Class_method` you just copied out of the output.
- A miss is actionable: `getclass HomePag` suggests real names instead of silently doing nothing.
- `--lib/--class/--func` also work on the full export, giving a **filtered** export: the
  function-scoped artifacts (`functions.txt`, `asm/`, `dart/`, `call_edges.txt`,
  `callgraph.dot`) shrink to the selection, while the object-layer dumps (`pp`, `objs`,
  `strings`, `libs`, `classes`, `arrays`, `maps`) stay complete because they are the index you
  pick from.

Cost, measured on a real Flutter app (10,245 functions): a full `--decompile` export takes
1.9s and writes ~1000 files; `dae info` / `dae getclass Foo` take 0.03s, `dae disasm` 0.05s,
and `dae callers` (the one query that disassembles every function) 0.18s. Snapshot parsing
itself is ~50ms — what progressive mode saves is the writing.

## Decompiler (experimental)

`dae --decompile` adds `dart/<library>.dart`: one pseudocode function per named function,
lifted from the disassembly through the same pipeline shape the sibling tools use
(machine-specific lift → basic blocks → emission).

What it does today:

- Real comparison conditions folded from `cmp`/`fcmp`/`test` + the branch (`if (rdx < 2)`).
- Framework register names (`PP`/`THR`/`SP`/`FP`, plus each platform's `register_aliases`) —
  including inside memory operands.
- Named direct call targets (`call router`), and `sub_0x...` for entries with no name.
- **Pool constants recovered**: `ldr x0, [PP, #0x17f8]` becomes `x0 = "Hello" /* pp+0x17f8 */`
  (string literals, immediates; non-string entries get a type comment). Verified against source
  on both arm64 and x64.
- **Field names, where they can be proved**: AOT deletes almost all of them
  (`Precompiler::DropFields`), so dae uses exactly two routes — the snapshot's surviving `Field`
  objects (name + word index via the Mint cluster) and implicit getter/setter names, whose body
  touches exactly one field. A name shows up attributed, without claiming the base's type:
  `x0 = mem((local_0), 0x17); /* _FutureListener.result (off 0x18) */`. Coverage: 60 recovered
  names / 218 annotated accesses on the arm64 sample, 367 / 438 on the Flutter app; the two
  routes independently agree on 40 of 41 entries and 0 anywhere conflict. `dae fields` lists the
  table, `text/fields.txt` carries it in the export.
- Stack slots rendered as locals (`local_8`), frame save/restore and barriers kept as
  `// frame:` / `// barrier:` comments, and the raw disassembly kept above each function so
  the output stays checkable.

**The output is valid Dart.** It parses and passes `dart analyze` with zero errors — machine
syntax is rewritten (`mem(base, disp)`, `memSet(...)`, `callIndirect(x8)`, `gotoLabel(0x..)`),
names are sanitised into identifiers (mixin-application class names contain `&`, which is a Dart
operator) and every file starts with a *pseudo-runtime* preamble declaring the machine-level
concepts plus whatever registers and cross-library call targets the body uses. That preamble is
not pretending the code compiles: it writes down where the machine layer ends and Dart begins.
Baseline: **680,515 → 0** errors on a 412-file / 10,245-function Flutter app, and 0 across all
27 corpora — see [`docs/DECOMPILER.md`](docs/DECOMPILER.md) for the table, the fix history and
the per-sample scores.

Control flow is **structured**: dominators give the natural loops (back edge = header
dominates its tail), then each region is emitted recursively — a conditional branch whose two
arms rejoin becomes `if/else`, `join == region end` counts as a valid diamond, an arm that
returns becomes `if (c) { return ... }`, a loop header becomes `while`, and an arm that leaves
the loop becomes `break`/`continue`. 87–92% of functions come out fully structured on the
corpora we gate on; the rest keep a `gotoLabel` and are marked with a `NOTE` header.

What it does **not** do yet: cross-block expression composition beyond a few levels, and type
recovery (everything is `dynamic`, field access is `mem(base, disp)`). Unrecognised instructions
are emitted verbatim as `// unmapped:` rather than approximated, and the count is printed in the
run summary — treat it as the quality dial.

Gates run on every change: `tests/dart_valid.rs` (real `dart analyze`, zero errors),
`tests/decompiler_shape.rs` (braces must balance in every emitted file — an unbalanced file means
a branch was silently dropped — every in-function statement must terminate, a structured-rate
floor, and **address self-consistency**: function ends look like terminators and direct calls land
on function entries) and `tests/field_names.rs` (the two field-name routes must agree, zero
conflicts, and every annotation in the output must exist in the recovered table — that is the
no-fabrication check). The address gate exists because an address-location bug on appended Mach-O
snapshots once made the decompiler read the wrong bytes while every name-based metric stayed green.

## Known limitations

- Addresses are file-offset space, not runtime VAs (matches the blutter reference)
- The snapshot/instructions sections are located in three layers: symbols (`kDartVm*` /
  single-snapshot `kDartSnapshot*`) → the Mach-O `LC_NOTE __dart_app_snap` appended blob
  (`dart compile exe`, some Flutter builds) → a magic-number scan inside the analysed slice.
  If only the last layer succeeds, instruction-section addresses are unavailable and dae says
  so; the address-dependent artifacts are then object-layer only
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