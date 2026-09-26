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
| hello_3.13.0 | 15 | 1174 | 1047 | 317 | 0 |
| hello_3.12.2 | 15 | 1176 | 1049 | 311 | 0 |
| hello_3.14b | 15 | 1161 | 1035 | 314 | 0 |
| hello_3.11.6 | 15 | 1133 | 1015 | 275 | 0 |
| hello_3.10.9 | 14 | 1104 | 987 | 274 | 0 |
| hello_3.9.4 | 14 | 1106 | 991 | 286 | 0 |
| hello_3.8.3 | 14 | 1103 | 989 | 286 | 0 |
| hello_3.7.2 | 14 | 1111 | 996 | 287 | 0 |
| hello_3.6.1 | 14 | 1108 | 1005 | 11 | 0 |
| hello_3.5.0 | 13 | 1111 | 1007 | 11 | 0 |
| hello_3.4.0 | 13 | 1138 | 1036 | 15 | 0 |
| hello_3.3.4 (x64 exe) | 14 | 1114 | 741 | 521 | 0 |
| hello_3.2.0 | 14 | 1143 | 1029 | 290 | 0 |
| hello_3.0.0 | 15 | 1207 | 1090 | 167 | 0 |
| hello_2.19.6 | 2 | 229 | 212 | 22 | 0 |
| hello_2.18.1 | 2 | 254 | 232 | 16 | 0 |
| hello_2.17.0 | 14 | 1231 | 1114 | 159 | 0 |
| hello_2.16.2 | 1 | 1086 | 995 | 142 | 0 |
| hello_2.15.0 | 13 | 1167 | 1052 | 162 | 0 |
| hello_2.14.4 (x64 exe) | 14 | 1094 | 698 | 4543 | 0 |
| hello_2.13.4 (x64 exe) | 17 | 1234 | 784 | 4705 | 0 |
| hello_2.12.4 (x64 exe) | 17 | 1187 | 815 | 4454 | 0 |
| hello_2.10.4 | 2 | 0 | 0 | 0 | 0 |
| **testing_app (real Flutter app, arm64)** | 412 | 10245 | 9436 | 60 | 0 |
Totals: 693 files, 33,616 functions, **0 analyze errors**.

Re-measured after the two changes below (shared-code chunks + an honest `unmapped` count):
old x64 executables went 52–58% → **64–69% structured**, and the `unmapped` column no longer
counts blocks that are never emitted.

Other gates hold on the same corpora: structured-rate floor 0.70 (measured 0.87–0.92 on the x64
corpora and 0.92 on the app), and address self-consistency (function ends look like terminators
82–96%, direct calls land on function entries 70–96%).

## Known weak spots (the backlog)

1. **Old x64 executables (2.12–2.14, 3.3.4): 64–69% structured, 4.4–4.7k unmapped lines.** Fixed
   so far: shared-code chunks (Dart AOT merges identical tails, so a branch target lands inside
   *another* function's byte range — `lift_chunks` adopts those as function chunks, bounded to 8
   chunks / 256 bytes and never a known entry) and the x64 lift for `push`/`pop`/`movzx`/`movups`
   and two-operand immediate binary ops. What is left is mostly `add`/`or`/`sub`/`inc`/`dec` with
   a memory destination (`add byte ptr [rax], 8`) and `.byte` runs where the table's code size
   cuts a function short of its last branch target.
2. `branch-to-done-block` (shared tail blocks) and `no-join:irreducible` — 809 of 10,245 app
   functions stay unstructured and keep a `gotoLabel`; the shape is a jump to an already-emitted
   block.
3. No type recovery: every value is `dynamic`, field accesses are `mem(base, disp)`, and locals
   are `local_m8`. Recovering types/fields is what would move the output from "readable
   pseudocode" to "recompilable code".
4. The preamble is per file and mechanical; a smarter version would only declare what is used
   and give the helpers real signatures.

## Adding a corpus

Drop an artifact into `dart/dart_samples/artifacts/` (scorecard picks up `.aot`, `.so`, `.exe`,
`.jit`, `.dylib`, `.bin`) or point `DAE_SCORECARD_EXTRA` at a colon-separated list of paths
(repo-external builds, e.g. a Flutter app bundle) and rerun the ignored test.