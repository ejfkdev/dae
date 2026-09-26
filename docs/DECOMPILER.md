# Decompiler quality baseline

The `--decompile` output is **pseudocode that is also valid Dart**: it parses and passes
`dart analyze` with zero errors. That is the acceptance bar, because it is the one judgement
that does not depend on our own opinions about shape — a real Dart front end has to agree.

中文版：[`DECOMPILER.zh.md`](DECOMPILER.zh.md)。

## How the bar is enforced

Two checks, both runnable from a fresh checkout:

```bash
cargo test --release --test dart_valid              # gate: every available corpus, 0 errors expected
cargo test --release --test dart_valid -- --ignored --nocapture   # full scorecard (all 25 SDK artifacts)
cargo test --release --test decompiler_shape       # shape + address self-consistency gates
```

`tests/dart_valid.rs` shells out to `dart analyze` over the emitted `dart/` directory and counts
`error -` lines. Warnings and infos (unused variable, unused import) are ignored — they do not
affect whether the output compiles. The test skips itself when `dart` is not on `PATH`, so it
never breaks a build on a machine without an SDK.

What "valid Dart" required (all of it is in `src/decompiler.rs`):

- Machine syntax is not Dart. `[x2, #0x3f]`, `#0x30`, `qword ptr`, `v2.2d`, `goto L40a8;`,
  `call foo` and `a, b = mem(...)` are all parse errors. Memory becomes `mem(base, disp)` /
  `memSet(base, disp, value)`, indirect calls become `callIndirect(x8)`, unwound edges become
  `gotoLabel(0x..)`, SIMD lanes become `v2_2d`.
- Names must be identifiers: mixin-application class names contain `&` (`Set&_LinkedHashBase&…`),
  which is a Dart operator; keywords (`rethrow`) and collisions with the pseudo-runtime
  (`toDouble`) are renamed. Two entries in one file that compute the same name get `_2`, `_3`.
- A per-file **pseudo-runtime preamble** declares the machine-level concepts
  (`mem`/`memSet`/`memRead2`/`callIndirect`/`gotoLabel`/`addr`/`abort`/…) and every identifier the
  body uses but does not define (registers, cross-library call targets). This is not pretending
  the code compiles — it writes down explicitly where the machine layer ends and Dart begins.

Fix history, in the order the analyzer found them (counts are for one real Flutter app,
412 files, 10,245 functions):

| stage | `error -` count | dominant cause |
|---|---|---|
| first measurement | 680,515 | `[..]`/`#`/`goto`/`call` in expressions |
| memory + call + goto rendering | 40,347 | undefined registers/functions |
| preamble declarations, name uniquification | 7,950 | `mem(mem(..))` nesting, `v2.2d` declarations |
| addressing modifiers, x86 size prefixes | 1,800 | `word ptr` inside `qword ptr`, `ds:` |
| conditions and `Node::Line` sanitising | 4 | `qword ptr [..]` inside `if (…)` |
| keyword/`print`/pair-store fixes | **0** | — |

## Baseline (2026-09-26)

27 artifacts: every SDK sample in `dart/dart_samples/artifacts/` plus a real Flutter app
(`testing_app`, macOS arm64, 10,245 functions). `structured`/`unstructured` are function counts;
`unmapped` counts instructions kept verbatim as `// unmapped:`.

| sample | files | functions | structured | unmapped | analyze errors |
|---|---|---|---|---|---|
| hello_3.13.0 | 15 | 1174 | 1051 (89%) | 170 | 0 |
| hello_3.12.2 | 15 | 1176 | 1053 (89%) | 170 | 0 |
| hello_3.14b | 15 | 1161 | 1039 (89%) | 170 | 0 |
| hello_3.11.6 | 15 | 1133 | 1019 (89%) | 153 | 0 |
| hello_3.10.9 | 14 | 1104 | 991 (89%) | 153 | 0 |
| hello_3.9.4 | 14 | 1106 | 995 (89%) | 155 | 0 |
| hello_3.8.3 | 14 | 1103 | 993 (90%) | 155 | 0 |
| hello_3.7.2 | 14 | 1111 | 999 (89%) | 155 | 0 |
| hello_3.6.1 | 14 | 1108 | 1007 (90%) | 1 | 0 |
| hello_3.5.0 | 13 | 1111 | 1011 (90%) | 1 | 0 |
| hello_3.4.0 | 13 | 1138 | 1040 (91%) | 1 | 0 |
| hello_3.3.4 (appended ELF blob) | 14 | 1130 | 1033 (91%) | 1 | 0 |
| hello_3.2.0 | 14 | 1143 | 1033 (90%) | 157 | 0 |
| hello_3.0.0 | 15 | 1207 | 1094 (90%) | 35 | 0 |
| hello_2.19.6 | 2 | 229 | 213 (93%) | 4 | 0 |
| hello_2.18.1 | 2 | 254 | 234 (92%) | 3 | 0 |
| hello_2.17.0 | 14 | 1231 | 1120 (90%) | 25 | 0 |
| hello_2.16.2 | 1 | 1086 | 999 (91%) | 21 | 0 |
| hello_2.15.0 | 13 | 1167 | 1059 (90%) | 26 | 0 |
| hello_2.14.4 (appended ELF blob) | 14 | 1123 | 1019 (90%) | 26 | 0 |
| hello_2.13.4 (appended ELF blob) | 17 | 1259 | 1133 (89%) | 42 | 0 |
| hello_2.12.4 (appended ELF blob) | 17 | 1212 | 1063 (87%) | 44 | 0 |
| **testing_app (real Flutter app, arm64)** | 412 | 10245 | 9502 (92%) | 3 | 0 |
Totals: 691 files, 33,711 functions, **0 analyze errors**.

The `unmapped` column counts instructions actually written out (it used to include blocks that
are never emitted, which made it read several times too high).

Other gates hold on the same corpora: structured-rate floor 0.70 (measured 0.87–0.92 on the x64
corpora and 0.92 on the app), and address self-consistency (function ends look like terminators
82–96%, direct calls land on function entries 70–96%).

## The trap this table keeps springing

Three times now the same failure mode has appeared, and it is worth stating plainly because the
metrics cannot see it: **the instructions image was located wrongly, so the decompiler read
different bytes.** Names, structure and validity all stay plausible — function names come from
Code objects, and valid-Dart-ness is about syntax, not semantics. Only *address self-consistency*
(test: entry looks like a prologue, direct calls land on entries) exposes it.

- arm64 `dart compile exe` (appended Mach-O, no symbols) — `instr_off = 0`
- x64 2.12–2.14 / 3.3.4 `dart compile exe` — the snapshot is appended as a **separate ELF**
  container addressed by a file trailer (`[offset][kAppJITMagicNumber]`); looking only at the
  executable's own symbols missed it. `hello_2.13.4`'s 1394 shared functions all shifted by
  exactly one constant (`0x462000`) once fixed — a single missing base, nothing else.
- The gate now covers both shapes: `hello_2.13.4` (appended ELF blob) is in the corpus list, and
  the prologue-rate floor (0.80; broken states measure 51–58%, correct ones 91–100%) would fail
  on either. The earlier "terminator rate" metric was retired after it turned out to be counting
  x64 `int3` padding — it reported 95.7% while the addresses were wrong.

## Known weak spots (the backlog)

1. Shared tails and irreducible loops: **forward** jumps into an already-emitted block are now
   handled by tail duplication (`dup_tail` re-emits the straight-line run, marked with a
   `duplicated tail` comment, bounded to 16 blocks / 256 statements per function or per run),
   which recovered 66 functions on the app. **Backward** jumps to a non-header block are
   genuinely irreducible loops (715 of them, verified: `is_loop_header=false`) — Dart cannot
   express those without `goto`, so they keep `gotoLabel` and the `NOTE` header.
2. `unmapped` is now down to single digits on most corpora (3 on the app, 1 on 3.3.4/3.4.0)
   after the last lift batch (`xchg`/`idiv`/`sbc`/`adc`/`umulh`/`clz`/`stxr`/`br`/`msub`/`fcvtm*`/
   SSE moves and conversions), with machine-only operations rendered as declared helper calls
   (`Op::Helper`) rather than `// unmapped:`. `csel` conditions fold through the preceding `cmp`
   now (`(x0 == x1) ? a : b` instead of `(hi) ? a : b`).
3. **Old x64 executables (2.12–2.14, 3.3.4) were never weak** — 64–69% structured was the wrong
   bytes talking. With the addresses fixed they sit at **87–91% structured, 21–231 unmapped
   lines**, the same league as the rest. What genuinely remains for them: `add`/`or`/`sub`/`inc`/
   `dec` with a memory destination (`add byte ptr [rax], 8`) and `.byte` runs where the table's
   code size cuts a function short of its last branch target.
4. No type recovery: every value is `dynamic`, field accesses are `mem(base, disp)`, and locals
   are `local_m8`. Recovering types/fields is what would move the output from "readable
   pseudocode" to "recompilable code".
5. The preamble is per file and mechanical; a smarter version would only declare what is used
   and give the helpers real signatures.

## Adding a corpus

Drop an artifact into `dart/dart_samples/artifacts/` (scorecard picks up `.aot`, `.so`, `.exe`,
`.jit`, `.dylib`, `.bin`) or point `DAE_SCORECARD_EXTRA` at a colon-separated list of paths
(repo-external builds, e.g. a Flutter app bundle) and rerun the ignored test.