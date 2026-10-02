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
cargo test --release --test field_names            # field-name recovery: cross-source agreement, zero conflicts
cargo test --release --test source_truth           # build tests/fixtures/truth.dart, decompile it, check against the source
DAE_TRUTH_ANDROID=1 cargo test --release --test source_truth   # same gate on a compressed-pointer arm64 build
cargo test --release --test code_coverage          # every published function name has a body (+ its own negative controls)
cargo test --release --test stub_names -- --ignored # sweep EVERY corpus for fabricated stub names (release-time gate)
DAE_TRUTH_ANDROID_SO=/path/libapp.so[,...] cargo test --release --test stub_names -- --ignored
DAE_REQUIRE_GATES=1 cargo test --release           # turn every "dependency missing, skipping" into a failure
```

`tests/stub_names.rs` exists because of a mistake made this session. Every other naming gate eats one
to three corpora, and the naming logic has **three** inputs that vary by target: SDK version (the
`DartThread` layout), architecture (arm64 vs x64 shapes), and **compressed pointers** (the
`heap_base` conditional field shifts every later field by 8). The `ArrayWriteBarrierStub_*` names
published for Reqable and Lark were wrong, and they passed every gate -- because the two corpora
checked first (material_3_demo, uncompressed; Weibo, whose 2.19.6 header already had `heap_base`)
were exactly the two where the wrong lookup still gave the right answer. The sweep re-derives all
four name families on every corpus it can find (29 with the mobile set: 23 446 names, 9 arm64,
5 compressed) against that corpus's own layout, and asserts the anti-vacuity floors that make
"0 suspicious" mean something (>= 15 corpora, >= 1500 names, >= 3 arm64, >= 20 in each of two
families). Negative-tested by reinstating the exact bug: hardcoding the stem to `array_write_barrier`
fails it with 5 suspicious names once a compressed corpus is in the set.

The last one matters more than it looks. Five of the six gate files consume corpora that are
gitignored (`testing/`, `dart/dart_samples/`), and they skip themselves when those are absent while
`cargo test` swallows the notice — a fresh clone therefore reports a green suite having measured
almost nothing. `DAE_REQUIRE_GATES=1` makes any such skip fail, which is the only way to
distinguish "the gates passed" from "the gates never ran".

**The `--no-default-features` build now compiles and tests clean, which it never did.** The `asm`
feature gates capstone and the whole decompiler, so a build without it has no `dae::decompiler` at
all -- and `tests/field_names.rs` and `tests/source_truth.rs` referenced that module unconditionally,
so `cargo test --no-default-features` **failed to compile**. That hid everything behind it: once the
compile was fixed, 16 more failures surfaced (15 in `cli_query.rs` plus `dart_valid`'s two
`dart/`-reading gates), all of them asserting on decompiler output that the configuration cannot
produce. Each is now `#[cfg(feature = "asm")]`, and the two files whose *helpers* then went unused
carry a file-level `#![cfg_attr(not(feature = "asm"), allow(dead_code, unused_imports))]`. Result:
default features 73 passed / clippy 0; `--no-default-features` 47 passed / 0 failed / 0 warnings, and
the binary still exports correctly (`stubs.txt`, `pp.txt`, `functions.txt` -- everything but `asm/`
and `dart/`). The lesson is the same shape as the register-alias one: **a configuration nobody runs
rots silently, and the rot hides behind the first error.**

`tests/source_truth.rs` is the only gate whose **input is source code**: it compiles
`tests/fixtures/truth.dart` with the local `dart`, decompiles the result, and asserts what the
source says must survive — every function the snapshot attributes to that library is rendered,
the string constants `main` reaches are inlined, `Account.withdraw` keeps its `-1` branch and its
comparison (when the compiler did not inline it), the output analyses with zero errors, and the
parse never drifts. The Android variant runs the same assertions on an arm64
**compressed-pointer** build produced by `flutter assemble` (it bypasses Gradle, whose first run
stalls on dependency downloads).

**The gates verify themselves.** A gate that can pass without measuring anything is worse than no
gate — this repo has paid for that twice (a prologue-rate check replaced a "last instruction is a
terminator" check that was happily counting x64 `int3` padding while the addresses were wrong).
So both `dart analyze` gates cross-check their own parsing against the tool's exit code and its
summary line (`No issues found!` / `N issues found.`): rc=0/1/2 must yield zero parsed errors and
rc=3 must yield at least one, and the summary line must be present at all. `dart analyze` on a
missing directory returns rc=64 with usage text containing no `error - ` lines, which the old
parsers read as "0 errors" — a clean pass on output that was never analysed. Each gate now carries
a `*_rejects_directory_it_never_analyzed` test that fails if that hole ever returns, and
`dart_valid` additionally asserts every corpus produced files and functions, so "empty output"
can no longer masquerade as "clean output".

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

## Baseline (2026-09-27)

26 artifacts: every SDK sample in `dart/dart_samples/artifacts/` plus a real Flutter app
(`testing_app`, macOS arm64, 10,245 functions). `structured`/`unstructured` are function counts;
`unmapped` counts instructions kept verbatim as `// unmapped:`. Totals as measured by
`cargo test --release --test dart_valid -- --ignored --nocapture`: **291 files, 24 253 functions,
0 `dart analyze` errors**.

`hello_2.18.1` is listed at 27 functions because that version **does not currently parse** — see
Known limitations in the README. It is kept in the table rather than dropped so the collapse stays
visible; `tests/ground_truth.rs` registers it in `KNOWN_COLLAPSED` and `FUNC_FLOOR` fails any new
sample that drops below 400 functions.

| sample | files | functions | structured | unmapped | analyze errors |
|---|---|---|---|---|---|
| hello_3.13.0 | 15 | 1174 | 1047 (89%) | 166 | 0 |
| hello_3.12.2 | 15 | 1176 | 1049 (89%) | 166 | 0 |
| hello_3.14b | 15 | 1161 | 1035 (89%) | 166 | 0 |
| hello_3.11.6 | 15 | 1133 | 1015 (90%) | 149 | 0 |
| hello_3.10.9 | 14 | 1104 | 987 (89%) | 149 | 0 |
| hello_3.9.4 | 14 | 1106 | 991 (90%) | 155 | 0 |
| hello_3.8.3 | 14 | 1103 | 988 (90%) | 155 | 0 |
| hello_3.7.2 | 14 | 1111 | 994 (89%) | 155 | 0 |
| hello_3.6.1 | 14 | 1108 | 1002 (90%) | 1 | 0 |
| hello_3.5.0 | 13 | 1111 | 1005 (90%) | 1 | 0 |
| hello_3.4.0 | 13 | 1138 | 1034 (91%) | 1 | 0 |
| hello_3.3.4 (appended ELF blob) | 14 | 1130 | 1026 (91%) | 1 | 0 |
| hello_3.2.0 | 14 | 1143 | 1026 (90%) | 152 | 0 |
| hello_3.0.0 | 15 | 1207 | 1088 (90%) | 33 | 0 |
| hello_2.19.6 | 15 | 1240 | 1117 (90%) | 31 | 0 |
| hello_2.18.1 | 1 | 27 | 26 (96%) | 0 | 0 |
| hello_2.17.0 | 14 | 1231 | 1112 (90%) | 23 | 0 |
| hello_2.16.2 | 1 | 1089 | 996 (91%) | 26 | 0 |
| hello_2.15.0 | 13 | 1167 | 1051 (90%) | 25 | 0 |
| hello_2.14.4 (appended ELF blob) | 14 | 1123 | 1011 (90%) | 25 | 0 |
| hello_2.13.4 (appended ELF blob) | 17 | 1259 | 1125 (89%) | 40 | 0 |
| hello_2.12.4 (appended ELF blob) | 17 | 1212 | 1056 (87%) | 42 | 0 |
| **testing_app (real Flutter app, arm64)** | 412 | 10245 | 9400 (91%) | 3 | 0 |
Totals: 691 files, 33,711 functions, **0 analyze errors**.

The `unmapped` column counts instructions actually written out (it used to include blocks that
are never emitted, which made it read several times too high).

Other gates hold on the same corpora: structured-rate floor 0.70 (measured 0.87–0.92 on the x64
corpora and 0.92 on the app), and address self-consistency (function ends look like terminators
82–96%, direct calls land on function entries 70–96%).

### Real applications (2026-09-27)

Everything above is `hello`-scale: ~1 200 functions per sample. Real apps are two orders of
magnitude larger, and `tests/app_truth.rs` covers three of them — the last two checked against
their actual source, which no other gate can do.

| artifact | Dart | functions | structured | unmapped | analyze errors |
|---|---|---|---|---|---|
| Reqable.app (macOS arm64, 26 MB) | 3.3.4 | 1 808 | 1 716 (94.9%) | 1 | 0 |
| Weibo `libapp.so` (android arm64) | 2.19.6 | 19 053 | 17 351 (91.1%) | 1 | 0 |
| Lark `libapp.so` (android arm64) | 3.6.1 | 3 517 | 3 374 (95.9%) | 1 | 0 |
| `material_3_demo` (5 107 source lines) | 3.13.0 | 15 082 | 13 950 (92.5%) | 3 | 0 |
| `animations` (2 108 source lines) | 3.13.0 | 11 102 | 10 264 (92.5%) | 3 | 0 |

For the two demos the source is known, so the output is judged *against it* rather than only against
itself:

| check | material_3_demo | animations |
|---|---|---|
| public classes/mixins/enums in `lib/` recovered | 85/86 = **98.8%** | 35/35 = **100%** |
| source string literals present in the output | 292/306 = **95.4%** | 111/114 = **97.4%** |
| source files mapping to a recovered library | 18/18 = **100%** | 21/23 = 91% |

The one missed type is `enum Value { first, second }` in `component_screen.dart`; that library *is*
in the output, so the enum was tree-shaken or canonicalised away rather than misparsed. The two
unmapped `animations` files are examples nothing references.

`app_truth`'s fast half (plain export + source comparison) takes ~2 s and runs in the normal suite;
the `--decompile` + `dart analyze` half is `#[ignore]`d because a million statements still take
a couple of minutes under `dart analyze` (dae's own half is seconds — see Performance below)
(247 s for both demos). Point `DAE_DEMO_ROOT` at a `flutter-samples` checkout built with
`flutter build macos --release`. The same binaries can be folded into the scorecard with
`DAE_SCORECARD_EXTRA=/path/to/App:/path/to/App2 cargo test --release --test dart_valid -- --ignored`.

## Performance

`DART_AOT_PROF=1` prints a per-phase breakdown of `render`. It exists because the release build
uses LTO, which collapses the call tree until `sample` attributes ~86% to `start` and no dae symbol
exceeds 0.6% — guessing from that produced two changes with no measurable effect before the
instrumentation found the real cause.

On `material_3_demo` (15,082 functions, 985,900 statements), and on real artifacts:

| artifact | before | after | output |
|---|---|---|---|
| `material_3_demo` | 113.5 s, 236 MB peak | **3.4 s, 217 MB** | byte-identical |
| Lark 3.6.1 (android) | 181.3 s | **1.6 s** | identical metrics, 0 analyze errors |
| Reqable.app 3.3.4 (macOS) | 156.0 s | **1.0 s** | identical metrics, 0 analyze errors |
| Weibo 2.19.6 (android) | ~214 s | **5.6 s** | identical metrics |

The cause was two per-function rebuilds of run-invariant data: `lift` called `roles(analyzer)`
itself, and `roles` builds the whole object-pool map (`BTreeMap<u64, String>`, 122,064 entries on
Reqable.app); and `Structurer` owned its `Roles`, so `emit_function` deep-cloned that same map once
per function. Both now borrow. Phases after the fix: lift 1.91 s (66.8%), emit 0.71 s (25.0%),
preamble 0.14 s, CFG 0.03 s.

This retires an earlier claim in this file's history that `--decompile` was dominated by ~1M
`format!` calls. Rendering was 5.7% of render; the allocation-heavy profiler leaves were the pool
map being rebuilt, not statement formatting.

### Round two: the register-alias table

With lift still at 66.8%, the next per-instruction cost was `mask_regs`, which rewrites capstone
operand text (`x15` → `SP`, `x27` → `PP`). It rebuilt its alias table on *every* call: clone the
profile's `register_aliases`, append `pp`/`thr` and nine hardcoded pairs, stable-sort by
descending key length, then run one `replace_word` per pair — each of which allocates a fresh
`String` and rescans the whole text. At ~1M instructions × 20 pairs that is ~20M allocations and
~20M full-text scans. The table is invariant for the whole run, so it is now built once in `roles`
and `mask_regs` is a single pass: tokenize on the same `[A-Za-z0-9_]` word boundary
`replace_word` uses, look each token up, copy separators in slices.

A single-pass lookup is **not** equivalent to sequential replacement in general, because the
replacements cascade. The arm64 profile maps `x29` → `fp` and `x30` → `lr` (lowercase), and the
hardcoded tail then maps `fp` → `FP` and `lr` → `LR`; after the descending-length stable sort the
three-character keys run first, so `x29` reaches the output as `FP`, not `fp`. `build_mask_map`
therefore resolves every key by *simulating the chain in the original pair order* rather than by
graph reachability — reachability would also fire on a value that equals an *earlier* key, which
the sequential algorithm never re-applies. Self-maps like `xzr` → `xzr` fall out correctly.

| artifact | round 1 | round 2 | output |
|---|---|---|---|
| `material_3_demo` | 3.4 s, 217 MB | **2.1 s, 188 MB** | byte-identical |
| ↳ `lift` phase | 1.95 s (66.7%) | **0.63 s (40.3%)** | 3.1× |
| ↳ `emit_function` | 0.73 s | 0.71 s | unchanged (not on this path) |
| Lark 8.0.2 (android arm64) | 1.56 s, 174 MB | **1.41 s, 167 MB** | byte-identical |

Timings are three interleaved A/B rounds (3.51/3.67/3.45 → 2.08/2.29/2.13 s); the same binary
varies ~35% under unrelated host load, so single runs are not evidence. Byte-identity was checked
with `diff -rq` on the whole output tree for `material_3_demo`, Lark, and five corpus variants
spanning Mach-O x64, ELF x64, ELF arm64 and SDK 2.10/2.14 — the arm64 corpus alone does not
exercise the x64 alias table. Metrics match exactly on every one (181,504 blocks / 985,900
statements / 13,950 structured / 1,132 unstructured / 3 unmapped lines).

Current absolute numbers on the released v0.1.8 binary, for readers who want "how fast is it now"
rather than the per-round deltas (host load 13–20 from unrelated processes, so treat these as an
upper bound): Lark 3.6.1 android, 25.6 MB, 25,183 table functions — **1.63 s** with `--decompile`;
Weibo 2.19.6 android, 9 MB, 19,053 decompiled functions / 1.53 M statements — **3.51 s**;
`material_3_demo` macOS, 14 MB, 15,796 functions — **2.37 s**; export without `--decompile` is
0.26 s for a 9 MB sample and 0.96 s for Lark. The round-1 table above still shows Weibo at 5.6 s
because that was its round-1 measurement; rounds 2 and 3 took it to 3.5 s.

Also in this round: capstone's `.detail(true)` was switched to `.detail(false)` at all eight
engine constructions. A grep confirms no detail API is used anywhere — only `mnemonic`, `op_str`,
`address` and `bytes` — so this is strictly less work, but the A/B showed **no measurable speedup**
(differences sat inside host noise). It is kept for that reason and is not credited with any of
the numbers above.

### Round three: memory, and where it actually is

Peak RSS was attributed by measurement, not guesswork, and two hypotheses died on the way:

- `dae info` (parse only) peaks at **41 MB**; the full export peaks at **151 MB**. So the decompiler
  is *not* the memory problem — parse is cheap and the export pipeline holds ~110 MB.
- Building with `--no-default-features` (which drops `asm` + `callgraph`) peaks at **60 MB**.
  Those two exporters therefore account for ~91 MB of the peak.
- The obvious suspect was wrong: `asm` writes each file from a `String::with_capacity(job.est)`
  buffer with up to 8 threads in flight, but the largest single file is 1.3 MB, so concurrent
  buffers cap near 10 MB — not the hog.

What the eight exporters actually do is run **concurrently** (`std::thread::scope`, one thread
each), so the peak is the sum of all their working sets, which is why RSS climbs monotonically and
never falls during export.

Inside `callgraph`, one real defect: edges were sorted with
`sort_by_key(|a| (a.from, a.to, a.to_text.clone()))`. **`sort_by_key` does not cache its key** — it
re-invokes the closure for every comparison — so this allocated a `String` per comparison:
96,904 edges × O(log N) ≈ **1.6M clones** on this corpus, and proportionally more on larger apps.
It now sorts by borrowed key (`to_text.as_str()`), which is the same order (`String` and `str` are
both bytewise-lexicographic) under the same stable sort. The merge of the per-thread partial
vectors also reserves its total length up front instead of doubling a ~14 MB `Vec`.

| mode | HEAD | after rounds 2+3 | output |
|---|---|---|---|
| export only | 169/164/175 MB, ~0.48 s | **138/140/149 MB, ~0.48 s** | byte-identical (506 files) |
| `--decompile` | 220/223/212 MB, 3.89/4.22/3.52 s | **180/180/173 MB, 2.55/2.08/2.31 s** | byte-identical |

Three interleaved rounds each, host load ~7.5 — absolute numbers are inflated but the pairing is
fair. Note what this does **not** claim: the callgraph fix bought memory and removed 1.6M
allocations, but export wall time did not measurably move (sorting 96k edges is already fast).

Byte-identity was re-checked with `diff -rq` on the whole tree for `material_3_demo` in *both*
modes, for Lark, and for the five corpus variants; `call_edges.txt` matches line-for-line
(96,904 / 12,011), which is the direct evidence that the new comparator orders identically.
One false alarm worth recording: a `diff -rq z_old z_new` run with relative paths from the wrong
cwd reported "differences" that were only `diff`'s exit code 2 for missing directories. Absolute
paths, and checking that `diff` prints nothing, is the reliable form.

### Round four: streaming the artifacts, then parallelising the decompiler (2026-09-28)

Rounds one to three made the decompiler itself fast. This round went after the two things that were
still holding the *whole export* back: artifacts being buffered in memory, and the decompiler being
single-threaded on an 18-core machine.

**Where the memory actually was** (measured, not guessed -- `DAE_SKIP_ASM` / `DAE_SKIP_CG`
isolation runs on material_3_demo, 15,082 functions):

| what is disabled | peak RSS | attribution |
|---|---|---|
| nothing | 137.6 MB | -- |
| `asm` | 100.0 MB | asm exporter ≈ **37.6 MB** |
| `callgraph` | 107.5 MB | callgraph ≈ **30.1 MB** |
| `--no-default-features` build | 60.5 MB | parse + object layer ≈ 41.9 MB (`dae info`) |

Two guesses were **wrong** and are worth recording. (a) It is not capstone: `dae disasm` on one
function is 42.8 MB vs `dae info` at 41.9 MB, so an instance costs ~0.9 MB and eight of them are
~7 MB. (b) It is not the artifact size either: the ten largest `asm/` files add up to 8.6 MB. The
bulk was **allocation high-water** -- `asm::write` accumulated each library into
`String::with_capacity(est)` where `est = 96 + mangled.len() + csize*12` *under*-estimates arm64 by
~2× (every 4-byte instruction renders as one machine-code comment plus one IL comment, ~90-100
chars), so each buffer grew by doubling, eight threads cycled through 489 jobs, and freed pages are
not returned to the OS.

**Fix 1 -- stream the artifacts.** `asm::write` now writes through a fixed 256 KB `BufWriter`
(per-thread cost independent of file size) instead of building the whole file. The decompiler was
worse: `render` returned `Vec<(String, String)>` holding **all 505 files = 63.2 MB** at once, and
`full = preamble + of` copied the largest one (4.2 MB) again. `render_into` now takes a sink, so
`write()` streams each library straight to disk while the stdout subcommands keep collecting.
Measured: 183.2-186.9 → 141.3-157.6 MB with `--decompile` (-18%), 140.0-144.1 → 128.0-131.2 MB
without (-9%).

> ⚠️ `write()` must still `create_dir_all(dart/)` **unconditionally**, even when it produces zero
> files. `hello_2.10.4.exe` / `hello_2.7.2.exe` have an object layer but no instruction table, so by
> design they emit no pseudocode -- and `dart_valid::full_scorecard` runs `dart analyze` on every
> sample's `dart/` directory, where "0 files, 0 errors" is a legal result and "directory missing" is
> a failure. Moving directory creation into the sink made the scorecard fail immediately.

**Fix 2 -- parallelise per library.** `render` was a single-threaded loop over 505 libraries:
2.49 s of the 3.0 s wall clock. Libraries are independent *except* for two first-wins rules, so
both are now settled by a cheap sequential pre-pass before any rendering starts:

* **file names** -- de-duplicated case-insensitively, second collision gets a `_2` suffix;
* **which library emits each entry point** -- code sharing means one machine-code address can back
  several `Function` objects, and the old code emitted it only in the first library that claimed it
  (a global `seen: BTreeSet`). The pre-pass freezes that into `owner: ep -> library index`.

Getting `owner` right needed one more piece: the single global `seen` was doing *two* jobs. Replacing
it with `owner` alone made the same library emit an address twice when two `FuncEntry` rows in it
shared one `ep` (a batch of identical getters), which showed up as **15,082 -> 15,367 functions** --
285 duplicates. A per-task `seen_local` restores the exact semantics.

Concurrency is the full `n_threads()` (= 8 here), the same knob every other exporter uses. The
per-thread working set *is* a whole library body -- the preamble can only be computed after the body
is rendered, so it cannot be streamed away, and library sizes are very uneven (largest 4.2 MB) -- so
the curve was measured rather than assumed (three runs per setting):

| concurrency | wall (s) | peak RSS (MB, mean) |
|---|---|---|
| serial (before) | 2.98-3.03 | 184.3 |
| 1 | 3.09 | 159.7 (streaming alone) |
| 2 | 1.83-1.90 | 175.0 |
| 3 | 1.43-1.51 | 178.7 |
| 4 | 1.23-1.25 | 205.0 |
| **8** | **0.96** | **206-235** |
| 12 | 1.12-1.24 | 235-241 |
| 18 | 1.08-1.15 | 267 |

Wall clock is stable; RSS carries ±25 MB of noise. **8 is the sweet spot and going past it makes
both axes worse**: this machine has 18 logical cores but only 6 performance cores, so beyond that
work lands on efficiency cores while a shared job queue means one slow thread holding a large
library delays the tail (12 and 18 threads are 0.1-0.3 s *slower* than 8). "Default to full
parallelism" therefore means `n_threads()` here, not the raw core count. `DAE_DEC_THREADS` overrides
it so the curve can be re-measured without a rebuild.

The body-buffer capacity estimate was also corrected. It used to be `n_fns * 768`, but measured on
material_3_demo the expansion is **~16.6 bytes of Dart per byte of machine code** (3.8 MB of code →
63.2 MB of output; `asm/` is 46.3/3.8 ≈ 12.2, which is exactly the factor `asm.rs` already used --
a useful cross-check), so the old estimate was **5.4× low** and every buffer doubled several times.
The pre-pass now sums `csize * 18` per library. Alternating A/B at 8 threads: wall 1.08-1.16 →
1.04-1.12 s, RSS mean 221 → 210 MB -- small, but consistent in the same direction in all three
pairs.

**Net, alternating A/B (4 rounds, material_3_demo):** with `--decompile` 3.04-3.05 s / 181-200 MB →
**1.42-1.43 s / 178-184 MB (2.13× faster, memory flat-to-lower)**; without it 0.56-0.58 s /
139-142 MB → **0.55 s / 124-130 MB (-9%)**. Artifacts are **byte-identical**: `diff -rq` clean on
material_3_demo (1011 files) and on six more corpora (arm64 Mach-O, x64 Mach-O, x64 ELF, two real
Android `libapp.so`, the stress sample). All gates green: 59 tests, `full_scorecard` (26 samples /
291 files / 24,253 functions / 0 `dart analyze` errors), `regress_all` 25/25, `check_profiles`
47/47, clippy 0.

### Round five: a self-inflicted 24.8x slowdown, and the two things that caused it (2026-10-01)

The stub-naming work above made export **11-25x slower**, and nothing in the test suite noticed.
Measured on the same binary, three runs each: `material_3_demo` 0.87 -> 1.33 s, Reqable
4.80 -> **54.3 s**, Lark 4.83 -> **119.6 s**. Both causes were per-address work that scaled with the
*instruction table*, which is why the small corpora hid it:

1. **An O(n^2) lookup.** `code_reg_stub_name` needed "how many bytes are left in the table entry
   containing this address", and got it by scanning all of `pc_offsets` **for every candidate
   address**. Lark has 59,772 stubs and 79,327 table entries -- about **4.7 billion** iterations.
   Fixed by building the unclaimed-entry index once (`StubIdx`, sorted by entry address because
   `pc_offsets` is non-decreasing) and binary-searching it: O(n + m log n).
2. **Decoding far more than the decision needs.** The same function disassembled its whole window
   (up to 4 KiB = 1024 instructions) with `disasm_all`, when the body it examines ends at the first
   terminator -- typically within 20 instructions. Switched to `disasm_count(.., 64)`.
   (capstone 0.12's lazy `disasm_iter` needs `&mut Capstone`; the call sites hold `&Capstone`.)
   64 is generous for the shapes actually observed -- the save-all prologue reaches the `CODE_REG`
   load in 11 instructions -- and **the failure mode of too small is "no name", never "wrong name"**.

After both: `material_3_demo` **0.82 s** / 144 MB (slightly *faster* than the 0.87 s baseline),
Reqable **5.70 s** / 888 MB, Lark **6.38 s** / 243 MB. The `disasm_count` change alone took Lark
7.51 -> 6.38 s and Reqable 6.33 -> 5.70 s, and all three corpora came out **byte-identical** to the
pre-optimisation export -- a pure speed win, verified rather than assumed. What remains over baseline
(Reqable +19%, Lark +32%) is the honest cost of naming 31,625 and 36,622 more call sites.

**Round six: decode each address once, not five times.** After the two fixes above, `names+stubs` had
become the dominant cost -- **3.43 s of Lark's 7.7 s (45%)** and **2.68 s of Reqable's 6.6 s (41%)**,
against 0.33 s / 0.64 s for the entire lift+structure+render main loop. The cause was structural:
`alloc_stubs_at` runs up to five namers over every unreferenced table entry (59,772 on Lark) and
**each namer disassembled its own window** (24 / 384 / 32 / <=4096 / <=4096 bytes), so the same bytes
were decoded up to five times -- about 238 instructions per address. (The write-barrier scan was *not*
the problem: its size pre-filter, `size % 32 == 0` and 64..4096, already cuts 59,772 entries to 5,050
before capstone is touched -- 8.4%; Reqable 9.6%.)

The fix is `disasm_stub`: one decode per address (window = the remaining bytes of the containing table
entry, capped at 4 KiB; at most 96 instructions), shared by all five namers, which now take
`&capstone::Instructions` instead of `(cs, addr)`. 96 instructions covers every shape on record --
`runtime_stub_name`'s save-all-plus-mirror body measures 32, and its old 384-byte window is exactly 96
arm64 instructions -- and where it does not, the failure mode is "no name", never "wrong name".
`inline_alloc_stub_name` additionally bails on the first mnemonic before building any operand strings,
so addresses that cannot match do not pay for string allocation.

Measured (`/usr/bin/time -l`, three runs each): `names+stubs` **3.43 s -> 1.00 s** on Lark and
**2.68 s -> 0.67 s** on Reqable; whole-export **7.71 s -> 2.68 s** on Lark and **6.58 s -> 2.38 s** on
Reqable. Both are now **faster than the pre-naming baseline** (4.83 s and 4.80 s) while naming roughly
40 000 more call sites than at the start of this work, so the naming rounds net out below zero cost.
material_3_demo 0.76 s, Weibo 1.17 s, ChatGLM 1.84 s. **All five corpora came out byte-identical** to
the pre-refactor export (`diff -rq`), which is the only reason this was safe to do as a pure refactor:
the namers' *criteria* did not change, only who decodes the bytes. Two window bounds did move
(`alloc_stub_name` 24 bytes -> the shared window; `code_reg_stub_name`'s fallback 256 -> 384), so
byte-identity was an empirical question, not an assumption -- and it held on 5 real apps plus all 25
`regress` archives.

> Two lessons, both about *how* this was caught rather than what broke. (a) **The suite cannot see
> performance at all** -- 71 tests, `regress_all` 25/25, `scorecard` 0 errors, all green while export
> took 25x longer. Only wall-clock measurement on the **large** corpora found it; `material_3_demo`
> alone showed +53% and would have looked like noise. (b) **Any new per-address scan must be asked
> "what does this scale with?"** -- the answer here was the instruction-table size, which varies
> 4.5x across the corpora (17,839 vs 79,327), so a cost invisible on the desktop samples dominates
> on the mobile ones.


## Three defects found by reading source against output (2026-09-28, all fixed)

Comparing decompiled output with the source of our own example programs, function by function,
found three defects that **every existing gate was blind to**.

1. **Pending values were silently discarded** (`nest_block`). On `Op::Note` / `Op::Cmp` and friends
   the code did `pending.clear()`. `push`/`pop` are `Op::Note`, and they are exactly where the
   call-argument preparation chain ends: on x64, `mov rcx,rax; sub rcx,1; push rcx; call fib` folds
   into `rcx = rax - 1`, which was thrown away -- so the output showed `fib()` with no argument and
   no line anywhere mentioning `n - 1`, and it did **not** count as unmapped (the instruction was
   recognised; only its result was dropped). Now flushed, matching `Call`/`Store`/`Branch`/`Return`.
   Measured: dart/ for material_3_demo grew 1,998,350 -> 2,165,737 lines (+8.4%) while
   `DecompileStats` did not move at all (it is computed before `nest_block`) -- which is why the
   summary metrics could not see it. Gate: `decompiled_body_covers_instruction_addresses`, counting
   how many real instruction addresses from `asm/` appear as statement addresses in `dart/`:
   70.1% before, 78.3% after, floor 0.75 (negative-tested). A narrower variant (flush only on
   `Op::Note`, +3.0% lines) was measured and rejected: it still dropped parameter loads such as
   `rax = mem(FP+0x10)` that are cleared at a `Cmp`.
2. **`condFlag` wrapped expressions that were already valid Dart.** `cbz`/`cbnz`/`tbz`/`tbnz`
   produce a complete boolean expression at lift time, but every branch then went through
   `fold_cond`, which matches on *mnemonics* and falls back to `condFlag("{mnem}")`. The fix
   distinguishes them by "contains a space" (mnemonics never do; both self-conditioning forms
   always do). Measured: 14,886 -> **2,841** occurrences, and the remainder are all genuine bare
   condition codes (`vc`/`vs`/`eq`/`ne`/`hs`/`lo`). Gate:
   `condflag_only_wraps_bare_condition_codes` (negative-tested). Example from a purpose-built
   stress sample (`switch` + ternary): `if (condFlag("w1 & (1 << 0) != 0"))` became
   `if (w1 & (1 << 0) != 0)`, which reads directly as the source's `n.isEven ? 'even' : 'odd'`.
3. **`dae classes` listed each library's top-level functions as a class with an empty name.** Empty
   sorts first, so `dae classes x | head -1 | cut -f3` returned an empty string (this actually broke
   an evaluation script), and the count was misleading (300 rows for this corpus, 12 of them
   nameless, while `text/classes.txt` holds 544 real Class records). They are now skipped and the
   count line states exactly how many were skipped and where to find them (`dae functions`,
   `dae members`). The same line now states the scope: this command lists only classes that own at
   least one function, whereas `text/classes.txt` lists every Class record -- the two differ a lot
   (animations: 2177 vs 3358, the rest having had their methods inlined or tree-shaken).

## Four more defects from a second stress sample (2026-09-28, three fixed, one reverted)

The first round compared source against output on `if`/loops/classes/collections. This round built a
**new** sample covering constructs none of the corpora exercise: `async`/`await`, `async*`/`yield`,
generics (`Box<T>`), extension methods, operator overloads (`+`, `==`, `hashCode`), cascades, an
`enum` with members, `mixin`, `abstract`, `late`, and nullable types. It compiles, runs, and its
decompilation passes `dart analyze` with 0 errors -- and it still exposed four defects.

1. **arm64 `cset`/`csetm` disappeared entirely** -- two bugs masking each other.
   `lift_one` built the ternary from the *raw condition code*: `(ne) ? 1 : 0`. `ne` is not a Dart
   identifier, so this should have been an `undefined_identifier` error; `csel`/`csinc` go through
   `sel_cond()`/`fold_cond()`, but `cset`/`csetm` were missing from the `matches!` list in `lift()`.
   That invalid text never surfaced because of the second bug: `nest_block` did not substitute
   pending values for `Expr::Text` (only `Expr::Mem` did), and `pending` is keyed by destination --
   so the following `x2 = (x2 << 1)` overwrote the `cset` entry and the statement vanished.
   **The net effect was a silently wrong value, not a missing line.** In the sample,
   `int get rank => this == Level.low ? 0 : 1` is inlined by AOT into
   `cmp x1, <Level.low>; cset x2, ne; lsl x2, x2, #1`; before the fix the output was just
   `x2 = x2 << 1`, where `x2` still held `4` -- the *interpolation array length* set eight
   instructions earlier. After: `x2 = ((x1 != BARRIER) ? 1 : 0) << 1`.
   A third piece was needed: when `NEST_MAX_DEPTH` blocks substitution, the pending value must be
   **flushed to a statement** rather than left droppable. `_BigIntImpl.get_hashCode` hit exactly
   that -- the depth limit stopped the fold at `asr r4, r5, #1`, then `ldur r5, [r2, #0xf]`
   overwrote `pending[r5]` and the whole hash computation (ternary included) was lost. It now emits
   `x5 = (((x4 == 0x10) ? -1 : 0) & ...) + ...` as its own line, which reads better than a
   110-character nested expression anyway.
   Gate: `cset_instructions_materialize_as_ternaries` -- per function, the number of `? 1 : 0` /
   `? -1 : 0` ternaries in the body must be >= the number of `cset`/`csetm` in that function's raw
   disassembly comment. Negative-tested: on v0.1.9 it reports **8 instructions / 0 ternaries /
   8 failing functions**; after the fix, 7 / 9 / 0.
2. **The raw disassembly comment block ran past the end of the function.** `lift` disassembles with
   a deliberate 16-byte lookahead (the Code object's size often cuts the last instruction in half),
   and `stmts` was correctly filtered by `stmts.retain(|s| s.addr < limit)` -- but `raw` was not.
   Every function therefore printed up to four instructions belonging to the *next* function
   (`_Record.get_hashCode`: entry `0x49e12c` + size `0x12c` => boundary `0x49e258`, yet the comment
   block reached `0x49e264`, and the extra `csetm x0, eq` is not this function's -- `dae disasm`'s
   IL stops at `0x49e254`). This is what made gate 1 mis-attribute one instruction. Now clipped.
   It is also why `dart/` got **smaller**: -2.5% to -3.5% across seven corpora.
3. **x86 `setcc` had no lift branch at all**, so it degraded to `// unmapped: setne dl`. That is
   honest (unlike defect 1 it never vanished, and it counted toward the unmapped metric), but the
   boolean condition was thrown away. `setcc` is the x86 counterpart of `cset` and now takes the
   same path; the condition code maps to a jump mnemonic by prefix (`setne` <-> `jne`), and only
   the 26 suffixes `fold_cond` actually handles are accepted -- anything else is left unmapped
   rather than inventing a `condFlag("j...")` name.
   Gate: `x86_setcc_materializes_as_ternary`. Negative-tested: v0.1.9 gives **9 instructions /
   0 ternaries / 8 unmapped**; after, 8 / 8 / 0.
4. **Reverted: substituting immediate literals into pending values.** Narrowing `subst_regs`'s
   "pure register alias" guard so that single-token *literals* also fold is tempting -- it turns
   `mov r17, #0x1cf2; movk r17, #0xd, lsl #16` from the self-referential
   `x17 = (x17 & 0xffff) | 0xd0000` into `x17 = ((7410) & 0xffff) | 0xd0000`, where the constant is
   readable. **It breaks `dart analyze`**: in the pseudocode every register and placeholder function
   is `dynamic`, and `dynamic - dynamic` stays `dynamic` (any operator allowed), but as soon as one
   side becomes an `int` literal the static type of `int - dynamic` is `num` -- and `num` has no
   `<<`/`&`/`|`. `_Smi.get_bitLength` turned into `((64) - (clz(x0))) << 1` and failed with
   `undefined_operator`; T4_blank failed the same way. It is not required for any of the three fixes
   above (with the flush from defect 1 the ternary materialises regardless), so it is out. Getting
   it back needs a self-consistent type system in the preamble (placeholder functions returning
   `int` instead of `dynamic`), which is separate work.

Across seven corpora (arm64 Mach-O, x64 Mach-O, x64 ELF, three real Android `libapp.so`, one
purpose-built sample) the net effect is a win on every axis at once: **non-`dart/` artifacts are
byte-identical**, **block and statement counts are unchanged**, `unmapped` lines drop
(42 -> 34, 166 -> 161, 25 -> 22), `dart/` shrinks 2.5-3.5%, and condition ternaries go from
**0 to 3-10 per corpus**. All standing gates stay green: 58 tests, `full_scorecard`
(26 samples / 291 files / 24,253 functions / 0 `dart analyze` errors), `regress_all` 25/25,
`check_profiles` 47/47, clippy 0.

## A third stress sample: w-register writes did not alias x-reads (2026-09-28, fixed)

The third sample covered what the first two had not: Dart 3 records, pattern `switch` expressions,
`sealed` classes, `sync*` generators, function typedefs, spread / collection-`if` / collection-`for`,
`rethrow`, `static`/`const`, and deliberately bit-twiddling code (an FNV-style hash with a rotate).
It compiles, runs, and decompiles to 0 `dart analyze` errors -- and the hash function exposed a
**silent wrong-value** defect.

On arm64 `wN` (32-bit) and `xN` (64-bit) are two views of one physical register: writing `wN` zeroes
bits 32-63 of `xN`. The output declares them as two independent `dynamic` variables, so "write `wN`,
then read `xN` with no intervening `xN` write" read a **stale** value. In `hashBytes` the source
rotate `((h << 5) | (h >> 27)) & 0xffffffff` compiles to `w4 = w1 << 5; w6 = w1 >> 27;` and the
output was `x0 = ((x4 | x6) >> 0) & 0xffffffff` -- `x4`/`x6` holding values from instructions ago.
After the fix it is
`x0 = ((((w1 << 5) & 0xffffffff) | ((w1 >> 0x1b) & 0xffffffff)) >> 0) & 0xffffffff`.

The fix emits an alias assignment `xN = wN & 0xffffffff` after every `wN` write; `nest_block` folds
it into later expressions. **Renaming `wN` to `xN` was rejected**: `w4 = w1 + w2` really means
`(w1 + w2) mod 2^32`, so a plain rename loses the truncation, and renaming only the write side would
leave every later *read* of `wN` undefined.

Measured on material_3_demo: stale reads **3 590 -> 16** (functions affected 1 135 -> 13, i.e.
7.6% -> 0.1%); statements +1.5% (985 900 -> 1 000 974) from the alias lines. Gate
`w_register_write_aliases_x_register` (floor 40 stale reads, and it asserts >= 20 `w` writes so it
cannot pass vacuously), **negative-tested**: on the pre-fix binary it reports 290 and fails.

Two measurement traps from this round, both worth keeping:

* **`DART_AOT_PROF` percentages can now exceed 100%** (lift 271%, emit 357%). That is not broken
  timing -- the per-phase numbers are *CPU time summed across threads* while the "main loop" line is
  wall clock. Run with `DAE_DEC_THREADS=1` for a single-threaded reading. The printout now says so.
* **A single wall-clock reading is unusable.** One run of material_3_demo came back at 3.42 s when
  three clean runs gave 1.09-1.22 s -- it had been started right after an `unzip` in the same
  command, on a machine that had been benchmarking for an hour. Always alternate A/B and take
  several rounds; peak RSS is far more stable than wall clock.

## Six more lift gaps closed by enumerating `// unmapped:` (2026-09-28)

Instead of writing yet another sample, this round just **counted every unmapped mnemonic across the
corpora** -- each distinct one is a concrete lift gap, so the enumeration is itself the bug list.
Before: material_3_demo 3, hello_3.13.0 (x64) 161, T4_blank (x64) 34.

| mnemonic | meaning | now rendered as |
|---|---|---|
| `addsd` `subsd` `mulsd` `divsd` (+`ss`) | x86 SSE scalar float, **two**-operand (`xmm0 = xmm0 op xmm1`) | `(a op b) /* float */`, sharing the arm64 `fadd`/`fmul` path |
| `comisd` `comiss` `ucomisd` `ucomiss` | float compare, sets flags only | folded into the `cmp` family, so the following `ja`/`jb` gets a real condition |
| `cmov<cc>` | conditional move (x86 sibling of `csel`) | `(cond) ? src : dst`, reusing the `sel_cond`/`fold_cond` path |
| `cinc` `cinv` `cneg` | arm64 aliases of `csinc`/`csinv`/`csneg` | `cond ? xn+1 : xn` / `cond ? ~xn : xn` / `cond ? -xn : xn` |
| `inc` `dec` | ±1 | `dst = dst + 1` / `- 1` |
| `cdq` `cqo` | sign-extend eax/rax into edx/rdx before `idiv` | `edx = ((eax >> 31) & 1) == 0 ? 0 : -1 /* cdq: … */` |

After: material_3_demo **3 → 2**, hello_3.13.0 **161 → 142**, T4_blank **34 → 9 (-74%)**.
`dart analyze` still 0 errors over 26 samples / 24 253 functions; all 60 tests green.

The x86 scalar-float case was the substantive one: `*sd`/`*ss` is how *every* `double`/`float`
arithmetic is emitted on x64, so missing them meant all float math in x64 snapshots showed up as
`// unmapped`. The two-operand form is why they were missed -- the arm64 path only accepted the
three-operand `fadd d0, d1, d2`.

**What is left, and a trap worth naming.** 121 of the remaining 142 are **instruction prefixes**
(`rep` 61, `std` 30, `cld` 30, `lock` 3) that capstone reports as separate instructions; fixing them
properly means combining a prefix with the instruction that follows (`rep movsb` is a memcpy loop),
not mapping the prefix on its own. The rest are `mul rdx` (x86 one-operand multiply writing
`rdx:rax` -- cannot be expressed as a single assignment without dropping the high half), `shld`/`shrd`,
`or mem(...), reg` (read-modify-write to memory), `bsr`, `subps`/`subpd`.

> ⚠️ Relabelling prefixes from `// unmapped:` to `// note:` would drop the headline number by 85%
> while adding **zero** information. `unmapped` is the quality dial precisely because it counts
> instructions whose semantics were not recovered; do not game it.

## A register-name substring match invented `ppmem(...)` and swallowed 1411 stores (2026-09-28, fixed)

Found by dispatching a subagent to audit Reqable (arm64, dart 3.3.4, obfuscated, `dedup_instructions`)
class by class. The tell was a **pure prefix correlation**: all 16 distinct `ppmem` displacements in
the whole artifact started with `0x27`, and `mem(..., 0x27*)` had **zero survivors**, while
`mem(PP, 0x5270)` / `0x26x` / `0x28x` were all fine. That distribution is the fingerprint of a
substring match, not of any semantic rule.

The pool-load test read `ops.contains(&rl.pp)`. Dart's arm64 pool pointer `PP` is physically `x27`,
and the displacement text `#0x27` **contains the substring `x27`**. So `stur x17, [x3, #0x27]` was
classified as a pool load and returned `Expr::Pool(0x27)`, with three consequences:

1. a **store became an assignment** -- direction reversed, so `memSet(x3, 0x27, x17)` vanished and
   `x17` was left holding an undefined identifier;
2. `Expr::Pool` renders as `pp[0x27]`, and the `sanitize_mem_refs` pass at the emitter's exit
   rewrites `[..]` into `mem(..)`, minting the identifier **`ppmem(0x27)`** out of nothing;
3. loads lost their base: `ldur x1, [x0, #0x27]` and the second-level `ldur x2, [x1, #0x27]` both
   rendered as the same `ppmem(0x27)`, aliasing two distinct indirections into one value.

Fix: word-boundary matching (`contains_word`, same boundary definition as the existing
`replace_word`). Measured on Reqable: `ppmem(` **1411 -> 0**, `mem(..., 0x27*)` **744 restored**,
and every swallowed `memSet(..., 0x27..., ...)` came back. The agent's original case `Agb.uzd` went
from `x17 = ppmem(0x27);` to

```dart
x17 = "autoCapture" /* pp+0x2a608 */; // 0xecd0f0
memSet(x3, 0x27, x17);                // 0xecd0f4
```

-- so the fix also **recovered a string literal** that the bogus pool index had been hiding.
Gate `no_register_substring_false_positives_in_output` (asserts 0 `ppmem(` and, to stay non-vacuous,
>= 50 `memSet` / >= 500 `mem`; this corpus measures 2475 / 9254).

The general rule worth keeping: **any test of the form `text.contains(register_name)` is a bug
waiting to happen.** `x27` is a substring of `0x27`, and `x1` is a substring of `x17`. Every
register-name lookup has to go through a word-boundary matcher.

## Clarity first -- attempted, and reverted (2026-09-28)

The premise is right: a bit test in the output is usually **an `if` the compiler optimised**, and
copying the machine form verbatim forces the reader to already know the object layout. The first
attempt acted on it and was **wrong**, so it is recorded here rather than deleted.

**What was tried.** `tbz xN, #0` / `tbnz xN, #0` → `isSmi(xN)` / `isHeapObject(xN)`, justified by
`tagging.heap_object_tag` = 1 and `smi_mask` = 1 from the profile -- i.e. bit 0 *is* the
Smi/HeapObject tag, read from the profile rather than hardcoded. On Reqable it produced 1 169
`if (isSmi(...))` + 58 `if (isHeapObject(...))`, drove the `& (1 << 0)` form from 1 232 to 0, kept
`dart analyze` at 0 errors, and fired on the w32-compressed Android corpus too. Every metric said
it worked.

**Why it is wrong.** The bit position does not establish the *meaning*. `tbz/tbnz xN, #0` is also how
an **unboxed integer parity test** compiles: the source `return n.isEven ? 'even' : 'odd';`
(`testing/stress/stress.dart:31`) becomes `tbnz w1, #0`, where `w1` holds an `int`, not a tagged
pointer. The rewrite rendered it as

```dart
if (isHeapObject(w1)) { x0 = "odd"; } else { x0 = "even"; }   // ← fabricated semantics
```

which tells the reader "if this is a heap object" when the truth is "if this integer is odd". The
previous form `if (w1 & (1 << 0) != 0)` is terse but **correct**. So the rewrite traded a correct
expression for a pretty, wrong one -- which is exactly the fabrication this project forbids, and it
was invisible to every gate: the output was still valid Dart, the counts still moved the right way.
Only reading the output against the source caught it.

Making the restoration sound needs proof that *this register currently holds a tagged value*, which
requires type or dataflow information the decompiler does not have (everything is `dynamic`).
Until then the bit test stays verbatim: it is what the machine actually does, and the reader can
decide whether it is a tag test or a parity test.

**Two things from this attempt are kept**, because both are independent of it:

* `lift()`'s "is this condition already an expression, or a mnemonic to fold?" test used to be
  `c.contains(' ')`. That proxy broke the rewrite (`isSmi(x0)` has no space, so it was treated as a
  mnemonic, missed `fold_cond`'s table, and fell into the catch-all `condFlag("isSmi(x0)")` -- the
  predicate ended up **inside a string literal**, worse than not restoring it, while the counts still
  looked right). It is now shape-based: a mnemonic is entirely lowercase letters and dots
  (`b.eq`, `jle`); anything with an uppercase letter, parenthesis or operator is already an
  expression. That is strictly more robust regardless of this feature.
* The gate `condflag_only_wraps_bare_condition_codes` **should have caught that and did not** -- its
  criterion was "contains a space or a comparison/logical/bitwise operator", and `isSmi(w0)` contains
  none. It now requires a `condFlag` argument to be a bare 1-3 lowercase-letter condition code.
  **The lesson: write gate criteria by shape, not by enumerating the bad cases you have seen so
  far** -- otherwise every new bug needs a new special case and the gate is always one step behind.

Also worth keeping: new placeholder functions must be declared explicitly in `PSEUDO_FUNCS`, not left
to the preamble's automatic `dynamic X;`. That automatic path is precisely why the invented
identifier `ppmem` survived `dart analyze` -- an unknown name becomes a `dynamic` variable and
calling a `dynamic` is legal.

**And a note on the remaining constants.** Auditing every numeric literal added to the code (not the
comments) this round leaves exactly one that came from measuring a single app: the decompiler's
body-buffer estimate `est += csize * 18 + 96`. The 18 is the bytes-of-Dart-per-byte-of-machine-code
ratio measured on material_3_demo (63.2 MB / 3.8 MB ≈ 16.6, rounded up); `asm.rs` independently uses
12 for the same kind of estimate and its own ratio measures 46.3/3.8 ≈ 12.2, which is the
cross-check. It is a **capacity hint only** -- over- or under-estimating changes how often the
`String` reallocs, never a byte of output -- so it cannot produce wrong results, but it is not
derived from anything universal and should be re-measured if the output format changes.
Everything else is architectural (`0xffffffff` for the 32-bit register view, `31`/`63` for
`cdq`/`cqo` sign extension), ISA-level (the 26-entry x86 condition-code whitelist, tied to
`fold_cond`'s own table), or a plain I/O buffer size.

## A field row that disappeared -- and why that is the fix working (2026-09-28)

The pre-release diff against v0.1.9 found exactly one changed byte outside `dart/`: `text/fields.txt`
went **634 -> 633 rows**, losing `_SyncStarIterator  _current  accessor  0x8`. Both binaries are
deterministic (three runs, identical md5), and it only happens on arm64 corpora, so it was traced
rather than waved off.

The accessor-inference route **runs the full `lift` pipeline** (`accessor_fields` calls `lift` on each
implicit getter/setter and reads the offsets out of the resulting `Stmt`s), so any lift change moves
`text/fields.txt`. Its soundness guard is: infer a field only when the accessor shows **exactly one**
distinct field offset and **zero** unclassifiable accesses.

`_SyncStarIterator._current_assign` contains two field accesses:

```
0x38163c: ldur r2, [r3, #7]      -> offset 0x7 (0x8 once the tag is removed)
0x381658: ldur r4, [r2, #0x27]   -> a second offset -- and 0x27 contains the substring "x27"
```

Under v0.1.9 the second one was swallowed by the pool-load substring bug (`ops.contains("x27")`
matched the displacement), classified as `Expr::Pool`, counted as *not* a field access -- leaving
exactly one offset, so the guard passed and the row was emitted. With word-boundary matching the
second access is correctly seen, `offs.len() == 2`, and the guard **declines**, which is what it is
for. Corroborating evidence that the old row was not sound anyway: this "setter" opens with two
*loads*, not a `stur`, so it is not the shape of a plain field setter at all.

So the row was produced by a bug cancelling out another bug's blind spot. **634 -> 633 is an increase
in soundness, not a loss of capability.** Worth recording because the coupling is invisible: nothing
in `text/fields.txt` suggests it depends on the decompiler's instruction lifter, and
`tests/field_names.rs` checks that the two routes agree and that every annotation exists in the
table -- it does **not** check that the row set is stable, so a lift change can silently move it.

## Two backlog items re-examined and deliberately left alone (2026-09-28)

Both were listed as "found, not fixed". Looking closely, neither is a naming or rendering tweak, and
guessing at either would trade a self-consistent reading for an unprovable one -- the same mistake as
the reverted `isSmi` restoration.

**Post-index stack slots are not mis-named; they need SP tracking.** The pair

```
str q0, [SP, #-0x10]!   ->  local_m10 = q0      (pre-index: SP -= 0x10, then store)
ldr q0, [SP], #0x10     ->  q0 = local_0        (post-index: load at SP, then SP += 0x10)
```

looks inconsistent, and at the machine level both touch the same slot. But dae names a slot by the
displacement **inside the brackets**, and `[SP]` has none, so `local_0` is self-consistent with that
model. Making the two names agree requires tracking SP across instructions (pre-index decrements,
post-index increments) -- real state, not a rename. Until that exists, forcing the names to match
would be a guess presented as a fact. 51 functions on material_3_demo show the pattern.

**The remaining x64 `unmapped` lines are prefixes and string ops, and my earlier count was wrong.**
The enumeration split on whitespace, so the 61 rows reported as `rep` were already capstone's
*combined* form `rep movsb mem(rdi), mem(rsi)` -- one unrecognised operation, not a bare prefix. The
142 remaining on hello_3.13.0 are therefore 61 string ops + 30 `std` + 30 `cld` + 3 `lock` + a few
`mul rdx` / `shld` / `shrd` / `or mem(...), reg` / `bsr`. Restoring a string op needs the
**direction flag**: `std; rep movsb; cld` is the fixed idiom for a backwards copy, so `rep movsb`
alone does not determine whether it copies up or down. Rendering it as a forward `memcpy` would be a
guess; and relabelling the prefixes from `// unmapped:` to `// note:` would cut the headline number
by 85% while adding no information, so that is off the table too.

## The lost loop-header stack guard (2026-09-28, fixed)

Instrumenting the structurer settled it. A temporary `DAE_DBG_ARM` print at the conditional-branch
arm fired for blocks 0x4bbdb8 and 0x4bbdc0 of `main` but **never for 0x4bbdac** -- the block that
holds the guard. So the guard's `b.ls` is not mishandled; it is never examined at all. The reason is
the loop-header path in `Structurer::seq`:

```rust
if let Some(&(_, exit)) = self.loops.get(&b) {
    let (cond, body_entry) = self.loop_shape(b);
    let mut body = self.body_lines(b);                      // non-terminator statements only
    body.extend(self.seq(body_entry, Some(b), depth + 1));  // header terminator never revisited
    out.push(Node::While { cond, body });
    cur = Some(exit);
    continue;                                               // skips the whole Branch match
}
```

`loop_shape` assumes the loop header's terminating branch **is** the loop condition. In Dart's
codegen the loop header is the **stack-overflow check**, and the real condition is one block later:

```
block 10 (header):  ldr BARRIER,[THR,#0x48]; cmp SP,BARRIER; b.ls 0x4bbe30   <- the guard
block 11:           cmp r1, #4; b.ge 0x4bbdf0                                <- the loop condition
0x4bbdec:           b 0x4bbdac                                               <- back edge to the header
```

So the header's `b.ls` is absorbed as the loop condition, `body_lines` emits only the `ldr`, and the
guard disappears -- leaving the out-of-line handler's `bl <overflow stub>` to be emitted inline right
after the load (which is why the two statements in the output are 0x64 apart). Confirmed on a second
function (`total`: header 0x4bbe4c, guard `b.ls 0x4bbe84`, back edge `b 0x4bbe4c`), and the handler
blocks are tail-duplicated (`main` has three copies at 0x4bbe28 / 0x4bbe30 / 0x4bbe38, all
`bl 0x4c3c40`).

**Fixed.** The discriminator that works is the **shape of the side block**, not loop membership:
the overflow handler is `bl <stub>; b <fallthrough>`, i.e. its unconditional branch target is exactly
the header's fallthrough successor (`is_rejoin_side_block`). When that holds, the header's branch is
a guard, so `loop_shape`'s fallback now enters the body via the fallthrough edge and `seq` emits the
guard as an `if` at the top of the body.

> ⚠️ The first attempt used "the branch target is outside the loop" and **failed**: the handler jumps
> *back into* the loop, so loop detection marks it `in_loop`, the predicate was always false, and the
> change moved 15 other `if`s without touching the target defect. It was reverted. The lesson that
> made the second attempt succeed: **verify the target instance itself first** -- unchanged structured
> rates across 7 corpora plus every gate green did *not* show that the first attempt had fixed
> nothing.
>
> Measured: unguarded **113 -> 0**, guarded 758 -> **875**, `if (` 5445 -> 5562 on sample_arm64;
> structured/unstructured **identical on all 7 corpora** (1060/115, 1047/127, 1051/116, 1063/156,
> 13947/1135, 1716/92, 1073/115); `dart analyze` 0 errors on full material_3_demo and Reqable
> exports; non-`dart/` artifacts byte-identical. The empty-`if` ratchet stayed at 109, so those 139
> lost branch edges are a **different** root cause, not this one. The ratchet ceiling is now 0.

**The fix has to distinguish "header's branch is the loop condition" from "header's branch is an
ordinary guard"**, and the natural discriminator is already available: `self.loops.get(&b)` yields the
exit block, so compare the header's branch target against it -- equal means condition, different
means a guard that must be emitted as an `if` at the top of the body. It is not applied yet because
this is the most regression-prone code in the project: the comment right below records that an earlier
over-eager `bail` here cost 713 branches their structure and dropped the structured rate from ~88% to
34% on an arm64 ELF corpus. Any change needs the structured rate re-measured on every corpus, not
just the gates. `stack_check_guards_do_not_regress` (113) and
`empty_if_without_else_does_not_grow` (109) are in place to catch the attempt getting worse; if this
and the empty-`if` defect share the root cause, one fix should lower **both**.
>
> **Answered (2026-10-01): they do not.** The guard fix left the empty-`if` count at exactly 109, and
> the empty-`if` defect was then fixed on its own terms -- see
> [Recording every conditional branch edge](#recording-every-conditional-branch-edge-2026-10-01).
> Its ceiling is now **5** (all five individually verified correct), so the two ratchets no longer
> move together.

## Naming 31% of the unnamed call targets by provable shape (2026-09-28)

`sub_0x…` call sites were the single largest quality gap: **42 759 of 86 825 direct calls (54%)** on
material_3_demo. Forensics first, because the answer decides whether this is fixable at all:

* those 42 759 call sites resolve to only **346 distinct addresses**, and **89.8% of them are
  stub-table entries** (no Code object);
* the **top 5 addresses account for 59%** of the traffic (`0x3dc328` alone is called 12 676 times);
* there is **no name source in the snapshot**: the profile has no Stub cluster, `grep` for
  `stub_name`/`StubNameList` finds nothing, and `ppobjs.rs` writes the literal string `"Stub"` for
  those pool entries. The only existing mechanism is `alloc_stub_name`, which decodes the class-id tag
  materialised in an allocation stub's prologue.

So naming can only come from **shape decoding**. Clustering all 346 addresses by their first
instructions (via the new `dae disasm <bin> 0xADDR`) gives 40 clusters; by call volume the largest is
**11 addresses / 22 847 calls (53%)** whose shape is:

```
str  x30, [x15, #-8]!
stp  x24, x25 / x20, CODE_REG / x19, x14 / x13, x12 / x11, x10 / x9, x8 / x7, x6 / x5, x4 / x3, x2 / x1, x0   (all pushed)
ldr  x24, [THR, #0x188] ; EnterFrame ; ldr x5, [THR, #0x488] ; ...
ldp  fp, lr ; ldp x0,x1 ; ... ; ldp x24,x25     (restored in exact reverse order)
add  x15, x15, #8 ; ret
```

Saving and restoring **every** argument and pinned register around a frame is not something any
ordinary Dart function does, so the shape is mechanically checkable and uniquely identifies a
calling-convention transition wrapper. `runtime_stub_name` requires: `str lr` first, >= 6 consecutive
`stp`, a `ret`, >= 6 consecutive `ldp` immediately before it, and **the first `stp`'s register pair
equal to the last `ldp`'s** (the mirror). It names them `RuntimeCallStub_0x<addr>`.

> **It stops there on purpose.** Which specific runtime entry it is, is *not* provable: the profile's
> `runtime_offsets` has 7 keys and contains neither `THR+0x188` nor `THR+0x488`, so naming a
> particular entry would be fabrication -- the same line the reverted `isSmi` restoration crossed.
> The address stays in the name so the 11 remain distinguishable.

**That justification was wrong, and the correction is measured.** It was concluded from
`runtime_offsets` having 7 keys. But that is the wrong table: `struct_tables::dart_thread` -- the per-version
`DartThread` layout dae already embeds and ships into the r2/IDA struct headers -- names **all 484
fields**. In dart 3.13.0, `THR+0x188` is `stack_overflow_shared_without_fpu_regs_stub`. So the
specific entry *is* provable from data already in the binary, and `RuntimeCallStub_0x...` understates
what the profile supports. It stays as shipped (it is not wrong, only less specific), and the sharper
naming is recorded as the next item in the backlog below.

> The first measurement of that item said **338 of 340** unnamed addresses (28,106 calls, 32.4% of
> all direct calls) were nameable this way. **That number was wrong by roughly 2x**, and the reason
> is worth more than the number: the scan read the disassembly of the whole *instruction-table
> entry*, and an entry can hold several stubs, so a stub was credited with its neighbour's `ldr`.
> Re-measured with the scan **cut at the first terminator** (`ret`/`brk`/`br`/`b`), i.e. scoped to
> the stub's own body: **102 of 340 addresses, 14,496 calls = 51% of the unnamed and 16.7% of all
> direct calls**. `AllocateDouble_entry_point`, `AllocateClosure_entry_point`,
> `AllocateTypedData_entry_point` and the whole 194-address `slow_type_test_entry_point` group
> **disappeared** -- they were all neighbours' instructions. This is the same class of error as the
> raw-disassembly block that once ran past a function boundary.
> **Rule: any per-address scan over a table entry must cut at the first terminator, or it silently
> attributes the next stub's code.**

The 9 addresses that failed the strict mirror check are now explained rather than mysterious: they
carry the identical save-all prologue but **end in `brk #0`** -- they call the runtime and never
return, so there is no restore to mirror. `0x3dc7b0` (5,730 calls) loads
`null_cast_error_shared_without_fpu_regs_stub` into CODE_REG, `NullCastError_entry_point` into r5,
`call_to_runtime_entry_point` into LR, calls, and traps. Rejecting them was correct for the *mirror*
criterion; it just is not the only provable criterion in this family.

Only **2 of the 11** addresses pass the strict mirror check on material_3_demo (the other 9 differ in
some detail); that is the intended behaviour -- naming 2 provably beats naming 11 guessingly. Those 2
cover **13 316 call sites**, so `sub_0x…` sites drop **42 759 -> 29 443 (-31%)** and the summary's
named-call count rises 40 485 -> **53 909**.

Verification: `dart analyze` 0 errors on full material_3_demo and Reqable exports; structured /
unstructured **identical on 5 corpora** (13947/1135, 1060/115, 1047/127, 1063/156, 1716/92); the
object layer is **byte-identical** to the pre-change binary (`pp.txt`, `objs.txt`, `classes.txt`,
`functions.txt`, `strings.txt`, `libs.txt`, `arrays.txt`, `maps.txt`, all of `asm/`) on 3.4.0, 3.5.0
and 3.6.1 -- the **only** file that differs anywhere is `text/stubs.txt`, which is the point. The
three `regress` archives were updated for that one file after verifying the object layer, and
`regress_all` is back to 25/25.

Gate `runtime_call_stub_names_are_provable` re-derives the shape **through a different path**: it runs
`dae disasm <bin> 0xADDR` and re-counts `stp`/`ldp`/`ret`/mirror from the text, so a broken
classifier cannot certify itself with its own logic (same pattern as `alloc_stub_naming`).

> Two measurement traps hit while building this, both worth recording. (1) `dae stubs` defaults to
> **200 rows**; the first classification run therefore saw a truncated stub table and concluded
> "99.4% of targets are in neither table" -- completely wrong. Use `-n`. (2) The shape matcher's first
> two versions matched **zero** addresses: `regs()` split on `]` so the memory operand was counted as
> a register, and the `add` before the `ldp` run was recognised by looking for `"sp"` in its operands
> -- but Dart's arm64 stack pointer inside Dart code is **x15** (`R15 = 15; // SP in Dart code.`), so
> capstone prints `add x15, x15, #8` and there is no `"sp"` substring anywhere.

## Names without bodies: the same defect twice, invisible to every gate (2026-10-01, fixed)

`text/functions.txt` listed 13,371 functions for Reqable. `asm/` contained **999**. The names were
right; the bodies were simply not there. Nothing complained: `dart analyze` passed, the structured
rate looked fine, `regress_all` was 25/25, and the call-naming metric even improved -- because every
one of those metrics is computed over *the functions that got emitted*.

The cause was in `Analyzer::code_size`, twice over, and both times it was the second half of a fix
that only landed its first half.

**Defect 1 -- a stale `idx < first_entry` guard.** An earlier change had established that
`first_entry_with_code` is *not* a reason to exclude an instruction-table entry (it cost 86% of
function names before that was understood), and `entry_for` was updated accordingly. `code_size`
kept the old guard, so for exactly those indices it returned `0`, `code_range` then returned `None`
on `size <= eo`, and the function had an address but no bytes. Measured blast radius:
**Reqable 11,207/13,371 = 83.8%**, **lark-android 19,921/25,183 = 79.1%**.

Why no gate saw it: `first_entry_with_code` is **0 in all 26 desktop corpora, all 25 `regress`
archives, and even a freshly built Flutter android-arm64 `app.so`**. The guard never fired anywhere
the suite looks. (It is not a version property either -- ChatGLM, weibo and CHSI are all 0 while
Reqable is 48,455 and lark 61,609.) This is the same shape as the earlier "every corpus is
`no-dwarf`, so address skew is untestable" blind spot.

**Defect 2 -- "the next entry" is not "the next *different* offset".** Dart 2.12-2.15 deduplicated
byte-identical `Instructions`, so several consecutive table entries share one `pc_offset`; only the
last of a run gets a non-zero length from `pc_offsets[idx+1] - pc_offsets[idx]`. Measured:
hello_2.12.4 **174**, 2.13.4 **217**, 2.14.4 **221**, 2.15.0 **212** names without bodies.
That this is compiler dedup and not a decoding error is independently evidenced by *who* shares an
address: 73 addresses in hello_2.12.4 are shared by 2..16 functions, and the sharers are semantically
the same body -- nine different `typed_data` classes' `get_elementSizeInBytes`, sixteen boolean
feature getters (`_isWindows`, `_setupCompleted`, `_enableSocketProfiling`, ...), nine error classes'
`ctor`/`get_stackTrace`. Equal `pc_offset` runs are 0 from 2.16.2 onward, so the fix is an identity
there.

The fix: length = distance to the **next strictly greater** `pc_offset`, found by `partition_point`.
The binary search is licensed by measurement, not assumption -- signed deltas were counted on eight
corpora (2.12.4/2.13.4/2.14.4/2.15.0/2.16.2/3.13.0 + Reqable + lark) and the **negative count is 0
everywhere**, i.e. `pc_offsets` is non-decreasing. Where there are no equal runs `partition_point`
returns `idx+1`, so the change is provably a no-op -- and it measured as one: `material_3_demo`
byte-identical, 21 of 25 `regress` archives byte-identical, and the 4 that moved differ in exactly
three files (`call_edges.txt`, `callgraph.dot`, `ida_script/addNames.py`) with the **entire object
layer identical**, including `stubs.txt`, the r2 script and `frida.js`.

Results after the fix:

| corpus | asm/ functions | dart/ blocks | structured | `dart analyze` |
|---|---|---|---|---|
| Reqable (arm64, 3.3.4) | 999 -> **9,630** | -> **11,237** | 10,916/321 = 97.1% | **0 errors** |
| lark-android (arm64, 3.6.1) | -> **17,914** | -> **19,555** | 18,537/1,018 = 94.8% | **0 errors** |
| full scorecard (26 desktop) | -- | 24,253 -> **24,497** | -- | **0 errors** |

Two internal consistencies fell out that corroborate the reading. The instruction table partitions
exactly: Reqable 57,960 = 11,237 with a Code object + 46,723 without (and `stubs.txt` grew
7,799 -> 46,723, because the Code-less prefix entries were being dropped for the same reason);
lark 79,327 = 19,555 + 59,772. And the address correctness was checked the established independent
way rather than by dae's own tables -- of the 8,631 newly recovered Reqable functions, **95.66%
begin with `stp fp, lr`** (the Dart arm64 `EnterFrame` prologue) against **81.58%** for the 999 that
already worked, with zero empty bodies and every size 4-byte aligned. Against the recorded thresholds
(correct 91-100%, skewed 51-58%) the recovered region is not merely acceptable, it is cleaner than
the region that was never broken.

Gate `tests/code_coverage.rs` asserts the invariant that was violated -- *every published function
name has a body* (`entry_for` yields an entry point => `code_range` yields a range), plus full
per-entry coverage whenever the corpus has an instruction table. It carries a **negative control**,
because "assert 0" is exactly the gate that silently measures nothing: the test reinstates each old
formula *on its own* and requires it to report orphans. Reinstating "subtract the next entry" must
report orphans on >= 1 corpus (2.12-2.15 guarantee 174/217/221/212, so this half is sensitive using
only in-repo corpora); reinstating the `first_entry` guard is sensitive only where
`first_entry > 0`. The first version of that control got the attribution wrong -- it combined both
defects in one formula, so on `first_entry == 0` corpora it degenerated into the other one and
reported "guard-sensitive on 4 corpora" for four corpora whose `first_entry` is 0. **When a gate has
two failure modes, each control must contain exactly one.**

The remaining blind spot is printed rather than papered over: with no `first_entry > 0` corpus in the
repository, defect 1 is only covered when `DAE_TRUTH_ANDROID_SO=/path/to/libapp.so[,...]` points the
sweep at a real large mobile build. With Reqable + lark + ChatGLM + weibo + CHSI supplied, the sweep
reaches 29 corpora / 241,699 table entries / 130,435 published functions / **0 orphans**, and both
controls are sensitive (B on 4, A on 2).

## `DartThread` was missing a conditional field, so every compressed-pointer target was 8 bytes out (2026-10-01, fixed)

This one started as "why does the fat-allocation namer fire on material_3_demo and nowhere else", and
turned out to be the most consequential bug found this session -- because it was not only silently
misnaming stubs, it was shipping a **wrong struct to IDA and r2 for every mobile corpus**.

`runtime/vm/thread.h` declares, in both 3.3.4 and 3.13.0:

```c
volatile RelaxedAtomic<uword> stack_limit_;
uword                         write_barrier_mask_;
#if defined(DART_COMPRESSED_POINTERS)
uword                         heap_base_;        // <-- conditional
#endif
uword                         top_;
uword                         end_;
```

`heap_base_` is the **only** `DART_COMPRESSED_POINTERS`-conditional *field* in `Thread` (each version
has three occurrences of the macro; the other two are accessor methods). Compressed pointers means
every mobile Flutter build, so on those targets every field after `write_barrier_mask_` sits 8 bytes
later than the non-compressed layout.

The 48 headers in `profiles/struct/` are **inconsistent about this**: 2.13.4 through 2.19.6 (14 files)
already contain `heap_base`, the other 34 do not. dae used them verbatim for both the shipped
`DartThread` struct and the thread-field lookup behind stub naming, with no compression handling.

Three code-observed offsets pin the correct answer for Reqable (dart 3.3.4, compressed). After
inserting `heap_base`, the emitted struct says `stack_limit` = 0x38, `top` = **0x50**,
`write_barrier_entry_point` = **0x1e8** -- and the binary agrees on all three: `ldr x16,[x26,#0x38]`
+ `cmp SP` + `b.ls` is `CheckStackOverflow`; the fat allocation stubs do `ldp x0,x2,[x26,#0x50]` and
`str x0,[x26,#0x50]`; the barrier sub-stubs do `ldr x30,[x26,#0x1e8]`. Before the fix the struct put
`top` at 0x48 and read 0x1e8 as `array_write_barrier_entry_point`.

**So two things were wrong, and one of them was mine, shipped earlier this session.** The
`ArrayWriteBarrierStub_x0` names published for Reqable and Lark were **fabricated**: the correct name
is `WriteBarrierStub_x0` (index 60, not 61). material_3_demo was unaffected because it is *not*
compressed, and Weibo was unaffected because its 2.19.6 header already had `heap_base` -- which is
exactly why the error survived: the two corpora I checked first were the two that happened to be
right. Fixing the lookup also **unlocked** the fat-allocation namer on mobile, because its
"the `ldp` base must be the field named `top`" check had been failing for the same reason.

**An independent tool agrees, field for field.** [aotopsy](https://github.com/) keeps its own THR
tables, checked against dart-lang/sdk by its `sdk-check` subcommand, and it carries *separate*
compressed and non-compressed variants. Its 3.9.2 pair reads:

| | `stack_limit` | `write_barrier_mask` | `heap_base` | `top` | `end` | `write_barrier_entry_point` | `array_write_barrier_entry_point` |
|---|---|---|---|---|---|---|---|
| `thrV392` (compressed) | 0x40 | 0x48 | **0x50** | 0x58 | 0x60 | 0x208 | 0x210 |
| `thrV392_nocompress` | 0x40 | 0x48 | -- | 0x50 | 0x58 | 0x200 | 0x208 |

Every field after `write_barrier_mask` is exactly **+8** in the compressed variant, `heap_base` sits
immediately after it, and `write_barrier_entry_point` precedes `array_write_barrier_entry_point`.
That is the same rule, the same insertion point and the same ordering dae now applies -- arrived at
from `thread.h` on one side and from a separate tool's sdk-checked tables on the other. It also
confirms the direction of the original error: with `write_barrier` *before* `array_write_barrier`,
reading Reqable's `0x1e8` as index 61 gave the **second** of the two, i.e. the wrong one.

The rule is "insert `heap_base` after `write_barrier_mask` **iff** the target is compressed *and* the
header does not already have it" -- so headers that already contain it are left byte-identical
(idempotent), which the measurements confirm: material_3_demo and Weibo named-call counts did not
move at all (77,071 and 108,194), while Reqable went 31,625 -> **40,548**, Lark 36,622 -> **43,182**
and ChatGLM 127,663 -> **142,415**. All five still `dart analyze` clean.

Gate `dart_thread_struct_gets_heap_base_only_for_compressed` needs no corpus: it runs the shipped
transformation over all 48 headers in both compression states and asserts the non-compressed output
is byte-identical to the input, the compressed output has exactly one `heap_base` immediately after
`write_barrier_mask`, `top` moves by exactly one field only when an insertion happened, headers that
already had it are unchanged, and no other field's order moves. 34 files need the insertion, 14 are
already correct.

> The general lesson is about **where the check lived**. Nothing compared the struct dae ships against
> the instructions dae disassembles, even though both were in hand -- and the disagreement is a single
> `ldr` immediate away from being obvious. Any per-version layout table should be cross-checked
> against at least one offset that the target's own code states unambiguously (`stack_limit` from the
> stack-overflow guard is the cheapest such anchor, and it is present in essentially every function).

## Inline allocation stubs: the same class name from a different shape (2026-10-01)

`alloc_stub_name` already named the *thin* form -- a 12-16 byte shim that materialises a class tag
with `mov`+`movk` and immediately `b`s into the shared allocator (`0x4294` -> `AllocationStub_Duration`).
Dart also **inlines the whole allocator** into a fat stub, and those had no name at all:
**13 addresses / 7,275 calls on material_3_demo = 8.4% of all direct calls**, the single largest
remaining unnamed family (42.7% of what was left).

The fat shape is ten mechanically checkable instructions:

```
ldp  <A>, <B>, [THR, #<top>]   ; bump pointer and its limit, in one load
add  <A>, <A>, #<size>         ; size MUST be a fixed immediate
cmp  <B>, <A>
b.ls <slow path>
str  <A>, [THR, #<top>]        ; commit the bump -- same field
sub  <A>, <A>, #<size-1>       ; back off to the tagged pointer, exactly size-1
mov  <H>, #<lo>
movk <H>, #<hi>, lsl #16       ; the object header
stur <H>, [<obj>, #-1]         ; stored one word before the payload
```

`<top>`'s displacement is looked up **by field name** in that version's `DartThread` layout, not
hardcoded (3.13.0 has it at 0x58; the write-barrier round is the cautionary tale). The class id comes
out of the header via the profile's own `tagging.cid_tag_pos`/`cid_tag_mask`, and the name is looked
up in the snapshot class table with the profile's predefined-cid table as fallback.

**The "fixed immediate" requirement is what keeps this honest.** Variable-length allocators
(`AllocateArray`, `AllocateTypedData`) take their size from a register, and the `mov x17, #0xfffa`
in their body is a *length bound*, not a header. Pairing "first `mov` + first `movk`" decodes cid 16
(`WeakSerializationReference`) at `0x3df2a0` and cid 95 (`TwoByteString`) at `0x3e057c` -- **both
fabricated**. Requiring `add <A>, <A>, #imm` plus the `stur <H>, [obj, #-1]` header store keeps those
out of the candidate set entirely (they never even reach the check).

All 13 decode to classes whose size matches: `_Mint`/`_Double` at 0x10 (header + one value),
`_Closure` at 0x30 and 0x40, `_Record` at 0x20 and 0x30 (Dart 3 records, by arity),
`_GrowableList` at 0x20, `_Float64x2`/`_Float32x4`/`_Int32x4` at 0x20. A third, independent
corroboration: the `_Closure` stub's slow path calls `AllocateClosure_entry_point` and the `_Double`
one calls `AllocateDouble_entry_point`.

Names keep the existing `AllocationStub_<Class>` convention with no address suffix. The same class can
have several specialisations (`_Mint` and `_Closure` twice each, `_Record` three times), but that is
not new: the thin shims already produce duplicates (1,858 names, 1,839 distinct --
`AllocationStub__RenderInputPadding` appears three times), and "two specialisations both allocate
this class" is true.

Measured effect on named direct calls: material_3_demo 69,796 -> **77,071 of 86,825 (88.8%)**, up from
46.6% before this round of work; Weibo 97,128 -> **108,194 of 123,659 (87.5%)**. All five real apps
still `dart analyze` clean.

**It fires on dart 3.13.0 and yields nothing on 3.3.4 / 3.6.1 -- and that is an unresolved data
question, not a namer bug.** Reqable's fat allocation stubs are the same shape but bump at
`[x26, #0x50]`, while the 3.3.4 arm64 `DartThread` header names `top` at **0x48** and `end` at 0x50;
3.6.1 is identical. So `inline_alloc_stub_name`'s "the `ldp` base must be the field named `top`"
check fails and it names nothing -- correctly, because guessing here would mean inventing which field
is the bump pointer. What makes this worth chasing rather than ignoring: `stack_limit` at **0x38**
*is* confirmed by the same binaries (`ldr x16, [x26, #0x38]` then `cmp SP, x16` / `b.ls` is
`CheckStackOverflow`), so the header is right at 0x38 and the code disagrees with it at 0x50 -- an
8-byte discrepancy somewhere in between. Either the 3.3.4/3.6.1 arm64 headers are one field out in
that region (which would make the `DartThread` struct dae ships to IDA/r2 wrong for every mobile
corpus from that point on), or those versions' allocators read a different pair. Settling it needs
the field-by-field offsets out of `runtime/vm/thread.h` **with all its `#if` branches resolved for
the mobile build configuration**, which is not something to guess at; until then the namer stays
silent on those versions. Measured prize if it resolves: 3 fat alloc stubs on Reqable alone account
for 9,191 calls.

The existing external-truth gate could not cover this and it is worth being explicit about why:
`ground_truth.rs::alloc_stub_naming` diffs against `.symtab`'s `Precompiled_AllocationStub_<Class>_<n>`
symbols -- the strongest check in the repo -- but its six corpora are **all x64** (`elf-x64.json`) and
this namer is arm64-only. T4_blank's 88 `AllocationStub_*` entries are all 16 bytes, i.e. thin shims;
a fat stub is at least 9 instructions = 36 bytes. So `inline_alloc_stub_names_match_the_class_table`
re-derives instead: it parses the shape back out of `dae disasm` text, recomputes the header from the
two immediates, decodes the cid with the profile's tagging (obtained in-process, a different code path
from production), and requires the resulting class name to equal the published one -- plus `size`
16-aligned, `sub` immediate exactly `size-1`, and header stored at `-1`. 19 stubs re-derived on
`sample_arm64`. Negative-tested: shifting the production cid decode by one bit fails it immediately.
Its first version asserted `size == table-entry length` and was **wrong** -- the entry also holds the
slow-path block (`0x4c650c`: object size 32, entry 100 bytes) -- so it now asserts `size <= entry`.

## `CODE_REG` was on the wrong register in every arm64 artifact (2026-10-01, fixed)

Found while reading the write-barrier forensics, not while looking for it: the raw capstone text for
block 17 of the barrier table was `mov x1, x23` and dae rendered it `mov r1, CODE_REG`, while block
18 was `mov x1, x24` and rendered `mov r1, r24`. Two adjacent blocks, one labelled as the code
register and the next not -- so one of the two labels had to be wrong.

It was the alias table. All three arm64 platform profiles carried, in the same file,
`registers.code_reg = "x24"` **and** `register_aliases["x23"] = "CODE_REG"`. Rendering uses the alias
table, so every arm64 artifact labelled x23 as `CODE_REG` and left the real one bare. Measured on
`material_3_demo`: **1,010 wrong `CODE_REG` in `asm/` and 3,014 in `dart/`**, against 559 `r24` in
`asm/` and 2,834 `x24` in `dart/` that should have carried the label.

Ground truth is the SDK, and it is unambiguous: `runtime/vm/constants_arm64.h` says
`const Register CODE_REG = R24;` in **every** version checked (2.12.4, 2.19.6, 3.3.4, 3.6.1, 3.13.0),
and R23 is only a member of `kAbiPreservedCpuRegs` with no named role. Two internal corroborations:
`non_field_base` lists x24 (the code register is never an object pointer) and not x23; and after the
fix, `ldr CODE_REG, [THR, #0x110]` in the runtime-call stubs reads as what it is -- loading that
stub's own `Code` object into the code register -- which the old rendering made nonsense of.

Both wrong aliases came from the Python reference implementation dae was ported from
(`dart_aot_export.py` has `"x18": "ARG2", "x23": "CODE_REG"` on one line), so they are recorded as
corrections 5 and 6 in `src/export/mod.rs`. The second one is a fabrication rather than a mix-up:
**`ARG2` does not exist in any version of `constants_arm64.h`**; R18 is documented as "reserved on
iOS, shadow call stack on Fuchsia, TEB on Windows" and the SDK states "We rely on R18 not being
touched by Dart generated assembly or stubs at all". Consistent with that, `ARG2`/`x18`/`r18` appear
**0 times** in the material_3_demo and Reqable artifacts, so removing the alias is a provable no-op
on output -- it only stops shipping an invented role name.

Fixed by pointing the alias at x24 and dropping x23 to no alias at all (it renders `r23`, which is
honest: nothing in the SDK gives it a role). Deliberately **not** done: adding aliases for registers
that do have roles but none in dae (`x21` DISPATCH_TABLE_REG, `x25` kWriteBarrierSlotReg,
`x4` ARGS_DESC_REG). That is a feature with its own output churn, not a correctness fix, and this
round was scoped to removing wrong claims.

Verification: the three real apps still `dart analyze` at **0 errors**, and structured/unnamed/named
counts are **identical to the unit** before and after (13,947/1,135 and 58,478 named on
material_3_demo; 10,916/321 and 28,440 on Reqable; 18,537/1,018 and 30,567 on Lark) -- a rendering
change moved no control flow. The `regress` suite is **blind to this**, and that is worth stating:
its three arm64 archives (3.4.0/3.5.0/3.6.1) hold a single `asm/` file each with **zero**
occurrences of `CODE_REG`, `x23` or `x24`, because those hello-world binaries never touch the
register. So the coverage lives in a new gate instead, `platform_register_aliases_are_self_consistent`,
which reads the six platform profiles through the shipping parser (`parse_platform`, the same
`include_str!` data the binary uses) and asserts that for every role in `registers`, any alias
bearing that role's name includes the physical register `registers` names. It needs no corpus, so it
runs in every checkout: 6 profiles, 51 (profile, role) pairs. The comparison is "is among", not
"equals", because a role can legitimately have two encodings -- `sp` maps to both x15 (Dart's stack
pointer) and x31 (the hardware encoding), and both should print `SP`. Negative-tested: pointing
`CODE_REG` back at x23 fails it immediately with the contradiction spelled out.

## One table entry, twenty stubs: naming the write-barrier family (2026-10-01)

The last unnamed-call cluster turned out not to be unnamed stubs at all. `material_3_demo`'s
instruction-table entry at `0x3e0a84` is **640 bytes**, and callers `bl` straight to `0x3e0aa4`,
`0x3e0ac4`, ... -- addresses *inside* the entry. Those targets are in neither the function table nor
the stub table, so no traversal that walks table entries can ever reach them. Measured: **10 such
addresses / 4569 call sites = 5.3% of all direct calls**, all inside that one entry, spaced exactly
0x20 apart.

Disassembling the entry shows why: it is **20 sub-stubs of 32 bytes each**, one mnemonic shape for
all of them (`str, str, mov, ldr, blr, ldr, ldr, ret` -- verified by raw capstone on two SDK
versions, two containers, two OSes: 160 instructions, **one** distinct shape). Each saves LR and x1,
moves a different register into x1, loads a code pointer out of the thread struct, calls it, restores
both in exact reverse order and returns. The forwarded register is the only thing that varies:
x0-x14, x19, x20, x23, x24, x25 -- precisely the registers that can hold a value being stored,
skipping every register with a fixed Dart role (x15=SP, x16/x17 scratch, x18 platform, x26=THR,
x27=PP, x29=FP, x30=LR).

**The offset must be read, never hardcoded.** `material_3_demo` (dart 3.13.0) loads `[x26, #0x1f8]`;
Reqable (dart 3.3.4) loads **`[x26, #0x1e8]`**. And in the per-version `DartThread` layouts those are
*different fields*: 0x1f8 in 3.13.0 is `write_barrier_entry_point` while 0x1e8 in 3.3.4 is
`array_write_barrier_entry_point`. Worse, the same offset can change meaning -- **0x1f8 is
`write_barrier_entry_point` in 3.13.0 but `array_write_barrier_entry_point` in 3.6.1** (lark), and
0x1f8 in 3.3.4 is `allocate_mint_with_fpu_regs_entry_point`. So the name is built by reading the
displacement out of the instruction and looking it up in that version's own layout header
(`struct_tables::dart_thread`, the same source the r2/IDA struct headers use), requiring the field to
end in `_entry_point`, and CamelCasing the stem: `WriteBarrierStub_x0` on 3.13.0,
**`ArrayWriteBarrierStub_x0`** on 3.3.4. Two different barriers, named differently, because the
profile says they are different. Nothing about the barrier's *semantics* is claimed, and the register
suffix claims only "this variant forwards that register" -- a one-to-one form-to-name mapping.

The `offset = field_index * 8` step is measured, not assumed: all **48** layout headers (24 versions x
arm64/x64) contain nothing but `__int64 <name>;` lines, and the derived offsets were cross-checked
field by field against the `dart_struct_fields-*.json` tables that carry **explicit** offsets
(~14k comparisons, **0 mismatches**).

Two bugs surfaced while wiring this up, both worth more than the feature:

* **A whole naming path was dead.** `call_edges.txt` resolves names through `name_alloc_stubs`, which
  called only `alloc_stub_name` -- so the previous round's `RuntimeCallStub_*` names reached `dart/`
  and `text/stubs.txt` but **never `call_edges.txt`** (14,000 sites). And even after chaining it, the
  names were still blocked: `name_map` gives *every* instruction-table entry a `sub_{ep:#x}`
  placeholder, and the target filter was "not already in `name_map`", i.e. placeholders counted as
  names. Both fixed; `name_alloc_stubs` now delegates to the one chain in `alloc_stubs_at`.
* **The same placeholder inflated the callgraph's own metric.** `edges_resolved` counted any non-empty
  name, so it reported 82,256/86,825 = **94.7%** -- the very number previously exposed as dishonest in
  the decompiler's `calls_named` (fixed in 7ea269a) and simply never fixed here. It now excludes
  `sub_0x...`.

Result on `material_3_demo`: named direct calls **53,909 -> 58,478**, `sub_0x` occurrences in `dart/`
**33,579 -> 28,553**, empty name column in `call_edges.txt` **4,569 -> 0**, and `call_edges.txt` and
`dart/` now report the **same** named-call count (58,478) from two independent code paths. Reqable
+896, lark +1312. All three still `dart analyze` clean; structured counts unchanged to the unit
(13,947/1,135, 10,916/321, 18,537/1,018), i.e. naming moved no control flow. Object layer of all 23
archived corpora byte-identical; the only files that moved are `text/call_edges.txt`,
`callgraph.dot` and (on 3.4.0/3.5.0/3.6.1) `text/stubs.txt`, and `regress_all` is back to 25/25.

`dae disasm <bin> 0xADDR` also accepts these addresses now, with a **32-byte** window that is not a
guess: the shape check requires exactly 8 instructions, and an entry is only split when *every* one of
its 32-byte blocks passes. A mid-block address (`0x3e0aa8`) is still refused with rc=1.

Gate `write_barrier_stub_names_are_provable` re-derives every published name from **three independent
sources**: `dae disasm` text (CLI + rendering path), the repository's `DartThread` header for that SDK
version (a different file and parser than the runtime's `struct_tables`), and the artifact itself. It
checks 19 of the 20 variants register-by-register (the 20th renders as `CODE_REG`, so it falls back to
the distinctness rule), asserts all 20 suffixes are pairwise distinct -- which is what catches taking
the `mov`'s *destination* instead of its source, since all 20 would then be identical -- and asserts
`stubs.txt` and `call_edges.txt` agree on every shared address.

Its negative controls were both run. Swapping the `mov` operand index fails it immediately. Hardcoding
the stem to `write_barrier` **passes on the in-repo corpus alone** -- because that corpus really is
3.13.0 -- and only fails once `DAE_TRUTH_ANDROID_SO` adds Reqable, whose expected name is
`ArrayWriteBarrierStub_x0`. That is a demonstrated hole, so the gate *prints* it: with a single
displacement in play it says out loud that hardcoding would go undetected, and with two or more
distinct stems it reports the anti-hardcoding coverage as earned. An earlier version of that
cross-corpus check asserted "different offsets => different stems" and was **wrong**: the same field
moves between versions (0x1e8 in 3.3.4 and 0x1f8 in 3.6.1 are both `array_write_barrier`), so it
failed on correct output. The per-corpus derivation is the real tripwire; across corpora the gate only
reports.

## 25 000 unnamed function bodies on mobile builds: measured, characterised, not fixed (2026-10-01)

`text/stubs.txt` used to describe itself as "instruction-table entries **without a Code object** (stub
prefix)". Neither half of that was true, and the second half hid the largest block of code dae does
not decompile.

What the file actually contains is the complement of `func_eps`: entries **no Function object
references**. dae never checks for a Code object. And they are not a prefix -- on Reqable
(`first_entry_with_code` = 48 455) **7 798** of the 46 723 sit at index >= that value while **9 530
named functions** sit below it, so the two kinds are interleaved. The header, the summary line, the
`dae help stubs` text and the README row all said otherwise; all four are corrected.

The reason it matters: those entries are **not all stubs**. Scanning the first two instructions of
every one of them across five corpora:

| corpus | `first_entry_with_code` | unreferenced entries | starting with `EnterFrame` | share | bytes |
|---|---|---|---|---|---|
| material_3_demo (3.13.0, uncompressed) | 0 | 2 735 | 34 | 1.2% | ~0 |
| Weibo (2.19.6, compressed) | 0 | 3 568 | 18 | 0.5% | ~0 |
| ChatGLM (3.11.6, compressed) | 0 | 4 428 | 18 | 0.4% | ~0 |
| **Reqable (3.3.4, compressed)** | **48 455** | 46 721 | **24 932** | **53.4%** | **8.09 MB** |
| **Lark (3.6.1, compressed)** | **61 609** | 59 770 | **43 195** | **72.3%** | **14.67 MB** |

`EnterFrame` here means `stp x29, x30, [x15, #-0x10]!` followed by `mov x29, x15` -- the standard Dart
arm64 function prologue, not something a stub emits. Their sizes run to 27 708 bytes with a median of
180. So on the two builds where `first_entry_with_code` is non-zero, **more than half of what dae
files as "stubs" is ordinary function code that never reaches `asm/` or `dart/`** -- 8.09 MB and
14.67 MB respectively, against 11 237 and 19 555 decompiled functions.

Two things this is *not* correlated with, both checked: compressed pointers (Weibo and ChatGLM are
compressed and sit at 0.4-0.5%), and obfuscation (Reqable's names are obfuscated -- `YDp`, `fOo` --
while Lark's are not, yet Lark has the larger share). The only clean correlate is
`first_entry_with_code > 0`.

aotopsy, run on the same Reqable binary, reports `instructions: 57960 entries (48455 stubs + 9505
code)`, describes the first group as **"48455 discarded Code objects"** under
`--split-debug-info`/`--obfuscate`, and then disassembles **all 57 960** as functions. So an
independent tool reads the same field the same way and simply decompiles both groups.

**What they are is now settled from SDK source, and it settles a second question too.**
`runtime/vm/app_snapshot.cc` (3.3.4) builds the table one entry per `InsertInstructionOfCode`
command -- i.e. **one entry per Code object** -- and asserts
`!Code::IsDiscarded(code) || (not_discarded_count == 0)`, so *all discarded Code objects come first*;
`first_entry_with_code` is set to the running total at the first non-discarded one. On the read side:

```c
if (code_index < first_entry_with_code) {
  *entry_point = d->instructions_table().EntryPointAt(code_index);   // entry point IS available
  return StubCode::UnknownDartCode().ptr();                          // the Code object is gone
} else {
  const intptr_t cluster_index = code_index - first_entry_with_code; // same order as Code cluster
  ...
}
```

So those entries are **real code whose Code objects were discarded**, entry point and all -- exactly
what aotopsy means by "48455 discarded Code objects". They are not stubs and they are not padding.

The same passage retroactively **justifies the `code_size` fix from source** rather than only from
measurement: the SDK hands back an entry point for `code_index < first_entry_with_code`, so treating
that region as size-less was wrong. And dae's index arithmetic matches the SDK's encoding --
`CodeIndexToClusterIndex` is `code_index - 1 - first_entry_with_code`, `GetCodeByIndex` reserves 0 for
`LazyCompile`, and dae's `entry_for` uses `ci - code_base_ref - 1` to reach the *instruction-table*
index, which is the right target since dae indexes `pc_offsets`.

**Both open questions are now closed, and the answer is that this is not a dae defect.**

*Why are they function bodies rather than stubs?* Not from the prologue alone -- VM stubs emit
`EnterFrame` too. The independent evidence is the **size distribution**, which separates three
populations cleanly on Reqable:

| population | n | median | p90 | p99 | max | total |
|---|---|---|---|---|---|---|
| Function-referenced (named, decompiled) | 11 234 | 272 B | 2 324 B | 14 168 B | 159 436 B | 12.14 MB |
| unreferenced, `EnterFrame` prologue | 24 932 | **180 B** | **704 B** | **2 352 B** | **27 708 B** | **8.09 MB** |
| unreferenced, no `EnterFrame` (real stubs) | 21 789 | 12 B | 28 B | 204 B | 1 020 B | 0.39 MB |

The middle row is the same order as the top row and three orders away from the bottom row. There is
no such thing as a 27 708-byte stub.

*Why does no Function reference them?* Because **the snapshot contains no Function object for them**.
dae reads each cluster's object count out of the stream itself (`count = read_unsigned()` immediately
after the cluster header), so it cannot under-count a cluster, and any misalignment would trip the
`cid > 60000` drift guard and warn -- Reqable parses with **0 warnings**. 13 371 Function records is
what the binary says. (The earlier hint from `closure_data: 9304` vs dae's 6 505 `_anon_closure`
is a ~2 800 gap, an order of magnitude too small to matter here, and is not evidence of truncation.)

So the metadata is **not in the file**: an obfuscated / `--split-debug-info` build externalises it,
which is exactly why the Code objects are discarded and why aotopsy reports "inline attribution
unavailable" for the same 48 455 entries. **There is no name to recover** -- dae and aotopsy are in
the same position, and inventing one would be fabrication. What remains is a pure *coverage*
question: emit those bodies into `dart/` as `sub_0x...` with no library and no class. That is a
different contract from the rest of the artifact and touches the sequential pre-pass that fixes file
names and per-entry-point library ownership -- the thing that keeps the parallel decompiler
byte-identical -- so it is recorded here rather than done. `dae disasm <bin> 0xADDR` **does** reach
them today, since they are stub-table entries.

## Recording every conditional branch edge (2026-10-01)

An `if` whose body is empty and which has no `else` --

```dart
if (x1 >= x0) {
}
x0 = local_m18; // 0x480ab0
```

-- is the decompiler *silently dropping a control-flow edge*. The machine code was
`cmp x1, x0; b.hs 0x480afc`, and `0x480afc` (`RangeErrorSharedWithoutFpuRegsStub`) is in the same
file, just hanging off a different branch. The reader is told "if x1 >= x0, nothing happens", which
is false. Measured before the fix: **109** sites on sample_arm64, **1596** on h212keep, and
**9817 across five real apps** (material_3_demo 1929, weibo 2972, chatglm 3209, lark 1203,
Reqable 504).

The `} else` variant (`if (c) { } else { … }`, 2560 sites on sample_arm64) is *not* this defect and
must not be "fixed" with it -- the gate that counts them keeps the two shapes apart, and an earlier
note records that treating them as one breaks the output.

### Root cause: `seq` returns empty for two different reasons

Instrumenting every `Node::If` construction site (temporary `DAE_DBG_EMPTYIF` probe, removed after
measurement) split the 109 sites exactly: **52** from the `find_join` path (25 where the join *is*
the true-target, 23 where the false-target was already emitted), **39** from `terminates(ti)`
(**37 of them with `stop == ti`**), **14** from the irreducible path, **4** from the mirror path.

`seq(x, stop)` returns an empty `Vec` in two situations that look identical from the outside:

1. `x == stop` -- the target is the region end, so its code is emitted *right after* the `if`.
   Leaving the body empty is then **correct**.
2. `x` is already in `done` (a shared block emitted elsewhere) or lies outside the region -- the
   body's statements, including `store`/`call` **side effects**, are skipped entirely. This is the
   lost edge.

### The fix: three tiers, most provable first (`Structurer::fill_branch`)

* **①** target is the block emitted immediately after the `if` (the join `j`, or the fallthrough for
  the terminating/mirror paths) -> leave empty; that *is* the truth.
* **②** target is an already-emitted shared block and the walk to the join is a **straight line** ->
  **tail-duplicate** it into the branch (`dup_to_join`, a sibling of the existing `dup_tail` with the
  stop condition widened from "terminator" to "terminator *or* join"). This is the same trade IDA and
  LLVM make for shared tails, and the file already had that precedent on the unconditional-branch
  path. It records the edge **and keeps the function structured**.
* **③** otherwise -> write the edge as `gotoLabel(0x<target>)`. The address comes from the
  instruction table, so it is a fact, not a guess -- the same discipline as `RuntimeCallStub_0x…`,
  which keeps the address instead of inventing a runtime-entry name.

Plus one real restructuring: when `terminates(ti) && stop == Some(ti) && terminates(fi)`, both paths
end at `stop`, so the honest form is the **mirror** (`if (!c) { <fallthrough side> }`) -- no empty
body, no goto, no metric cost. That single case was 37 of the 39 `terminates(ti)` sites.

Three things that had to be pinned down the hard way:

* **The mirror needs `terminates(fi)`.** Reaching that arm means `find_join` returned `None`, i.e.
  `ti` and `fi` have *no* common successor -- so "both paths reach `stop`" does **not** follow
  automatically. Without the guard, a non-terminating `fi` would fall through into `ti`, writing an
  edge into the artifact that does not exist in the binary.
* **The irreducible path's fallthrough is `None`, not `stop`.** It pushes `Goto(fi)` and `break`s
  right after the `if`, so what follows the `if` is the *false* branch's goto, not `ti`'s code; tier
  ① does not apply. Those functions are already `unstructured` (the path calls `bail`), so the goto
  costs nothing.
* **An empty `els` is filled too.** `find_join` only guarantees both sides *eventually* reach `j`;
  the shared block's statements in between are skipped just the same, and they have side effects.
  A first version that filled only `then` left 483 such sites on h212keep silent.

### Measured (base -> fixed)

| corpus / app | no-else empty `if` | structured rate | tail-duplicated | `gotoLabel` | `dart/` bytes |
|---|---|---|---|---|---|
| sample_arm64 | 109 -> **5** | 90.21% -> 90.04% | 85 | 262 -> 308 | +0.5% |
| T4_blank (x64) | 118 -> **6** | 87.60% -> 87.28% | 64 | 507 -> 558 | +0.4% |
| hello_3.12.2 (x64) | 103 -> **5** | 89.20% -> 88.95% | 100 | 269 -> 309 | +0.6% |
| hello_2.13.4 | 102 -> **6** | 89.79% -> 89.56% | 58 | 514 -> 554 | +0.3% |
| h212keep (elf arm64) | 1596 -> **737** | 88.40% -> 76.57% | 497 | 1409 -> 1882 | +2.8% |
| material_3_demo | 1929 -> **62** | 92.47% -> 91.96% | 1467 | 3726 -> 3965 | -- |
| Reqable | 504 -> **2** | 97.14% -> 96.97% | 435 | 1391 -> 1445 | -- |
| lark | 1203 -> **15** | 94.79% -> 94.48% | 2399 | 1966 -> 2126 | -- |
| weibo | 2972 -> **67** | 91.08% -> 90.23% | 2233 | 8067 -> 8600 | -- |
| chatglm | 3209 -> **70** | 91.95% -> 91.48% | 3111 | 6631 -> 7123 | -- |

`dart analyze`: **0 errors** on all five real apps (30 892 / 30 455 / 57 940 / 58 112 / 67 366
warnings, all `unused_local_variable`, and *fewer* than before the fix -- a duplicated body gives the
register a reader). Zero non-ASCII across all 14 797 artifact files. `unmapped` lines unchanged
(weibo/chatglm 1 -> 1), named direct calls unchanged (m3 77 071/86 825, Reqable 40 548, lark 43 182,
weibo 108 194, chatglm 142 415), and `regress_all` 25/25 -- the archives hold `text/`, `ida_script/`,
`r2_script/`, `frida.js` and `callgraph.dot` but **not** `dart/`, so this change touches none of them.

**The structured rate is the price, and it is a reclassification, not a regression.** `Node::Goto`
marks the whole function `unstructured`; those functions were counted as structured *precisely
because* the edge was hidden. Tail duplication buys most of it back (h212keep: 61.2% with gotos only
-> **76.6%**; sample_arm64 86.4% -> **90.04%**). The lowest corpus is 76.57% against a
`STRUCTURED_FLOOR` of 0.70, so the floor was **not** lowered.

### The five remaining sites are correct, not leftovers

Each was checked against the raw disassembly emitted in the same file:

* three are `ti == fi`: `0x4b10dc: b.eq #0x4b10e0` where the *next* instruction is `0x4b10e0`. Both
  outcomes go to the same place, so the `if` genuinely does nothing (`Uri_replace`,
  `SimpleUri_replace`, `RegExp_factory_ctor` -- all string-identity checks left over after inlining).
* two are tier ① on the outer `if`: `RangeError_checkValidRange`'s `0x481d3c: b.lt #0x481d48` has
  join `0x481d48`, whose code (`tbnz x1, #0x3f`) is emitted immediately after the `if`.

### Gate changes

* `empty_if_without_else_does_not_grow`: ceiling **109 -> 5**, and a new **floor** on the
  tail-duplication count (`duplicated branch body` >= 40, measured 85) so a refactor that silently
  disables tier ② cannot pass by "changing how it loses the edge". Both assertions were
  **negative-tested**: stubbing `dup_to_join` to `return None` drops the count 85 -> 25 and fails the
  floor; stubbing `goto_if_empty` leaves duplication intact and pushes no-else 5 -> **43**, failing
  the ceiling.
* `post_index_stack_slots_do_not_regress` now counts **distinct (file, machine address)** instead of
  raw occurrences: 942 -> **926**, and base and fixed both give 926 while the raw counts differ
  (942 vs 943). The extra raw hit was a *copy* of an existing statement, which is not a naming
  regression -- a count-based ratchet that moves when code is duplicated would have to be re-based on
  every such change. Added a floor (>= 500) so a broken detector cannot pass by reporting 0.

## Known gaps (measured, not fixed)

* **Statement order does not follow address order**: 21,826 sites = **2.74% of statements**,
  touching **36.1% of functions**. Criterion: a statement reading a register appears earlier in the
  text than the assignment that defines it, *and* that assignment has a lower machine address --
  which excludes live-in parameters (a first version of the metric counted them and overstated the
  rate as 5.52%). **This cannot be fixed by sorting on address**: a folded expression is only
  correct because it appears *before* the statement it folded (`rax = rcx + rax // 0x5e3a4` reads
  the pre-add `rcx`), so reordering would double-count. Fixing it means choosing between liveness
  analysis to suppress redundant landings, or dropping expression folding altogether.
* **Return values are mostly not recovered**: bare `return;` 17,238 vs `return <expr>;` 790 (95.6%).
  Not "never": both case branches of `classify` emit `return x0;`. The statistic is dominated by
  void functions and epilogues.
* **Calls carry no arguments**: every call renders as `f()`. Argument-preparation instructions now
  land (defect 1), so the arguments are recoverable from context, but the call line itself has none.
  **Not a new finding** -- item 5 of the backlog below already lists it, and records that it was
  **attempted and reverted**: without a verified per-ABI clobbered-register table there is no real
  liveness, so writing arguments would pass off a register written before an *earlier* call as this
  call's argument (the truth corpus caught exactly that: x0 written 8 instructions and one call
  earlier).
* **Closures lose their enclosing function** (`_anon_closure` instead of
  `_BigIntImpl._cachedDivRemResultValue.<anonymous closure>`). This is blutter-compatible naming, and
  unlike the pool-name gap below **the data is already parsed**: the `ClosureData` cluster carries
  **2 refs in every profile from 2.14.4 through 3.13.0**, and the 2.14.4 profile labels them
  `parent_function` and `closure` -- newer profiles read the same two refs but leave them unnamed, so
  ref[0] is sitting there unused. Two things must be established before projecting it: (a) the ref
  *order* is the same in every version (only 2.14.4 documents it -- prove it by checking that ref[0]
  resolves to a Function and ref[1] to the closure's own Function, on the `.symtab` corpora where the
  qualified name is independently known); (b) it is a deliberate artefact-wide rename, because
  `_anon_closure` appears in `text/functions.txt`, the IDA/r2 scripts and `frida.js`, so every
  `regress` archive has to be re-cut. Measured frequency on `.symtab` corpora: 40 sites in
  hello_2.15.0, 26 in hello_3.13.0, all of them "class/prefix differs only".
* **Object-pool names are still not projected into the IDA/r2 scripts** (blutter emits ~52,700
  `pp.*` flags). The data exists and `dae pp` / `dae findrefs` query it.

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

## Value recovery: pool constants

`ldr x0, [PP, #0x17f8]` is a load from the **object pool**. dae resolves it against the pool
entries it already parses, so the literal shows up in the pseudocode:

```dart
rax = "Hello" /* pp+0x17f8 */;   // was: rax = mem(PP + 0x17f7);
```

Verified against source on both architectures: `"Testing Sample"` (from the app's
`lib/main.dart`) appears three times in its output, `"Hello"` and `" fib(20)="` from
`hello.dart` appear in the 2.15.0 one. Counts of inlined literals: app 1922, hello_3.13.0 556,
hello_2.15.0 579, hello_2.13.4 448, hello_3.3.4 403.

**A string literal is never folded into an arithmetic expression.** The register holds the *address*
of the pool slot; the literal is what lives *at* that address — substituting one for the other is a
category error, and Dart rejects the result: `mem((" fib(20)=") + rdx*8 + 0x17)` is `String + int`,
i.e. `argument_type_not_assignable`. That is exactly how `hello_2.18.1` produced the corpus's only
analyze error. The literal still appears on the line that loads it, which is where it belongs, and
non-arithmetic uses (`call(x0)`) are still substituted.

Three things this needed, each found by a wrong result first:

- **The pool pointer is tagged on x64.** `[PP + 0x17f7]` addresses the entry at `0x17f8`
  (tag 1), so the lookup tries the offset and offset+1 — pool slots are 8 bytes apart, so the
  two candidates cannot both be entries.
- **Not every string survives the trip.** `describe_into` recognises strings by cid
  (93/94), which older profiles number differently — those came out as the *class name*
  `String`. Resolving by ref (`sref_str`) instead is version-independent.
- **The pool contains binary junk** (Unicode data tables). Only printable-ASCII, ≤ 60 chars
  strings are inlined, escaped properly (`"`, `\`, newlines); the rest keep the memory form
  with a type comment. That also keeps the "artifacts are pure ASCII" rule intact.

Non-string entries get a type comment (`mem(PP, 0x2d8) /* Field */`) rather than a value —
they are not Dart expressions, and inventing one would be worse than saying nothing.

## Field names: what survives, and the two ways to prove one

Mobile targets (compressed pointers) are supported since 2026-09-26 — see
[`COMPARISON.md`](COMPARISON.md) for what that took and how it was verified on real apps.

AOT deletes almost every field name. `Precompiler::DropFields` keeps them only outside PRODUCT
builds, so a release binary retains a **handful**: 60 on the 3.13 arm64 sample, 366 on a real
Flutter app — against hundreds of classes and thousands of fields. Everything else is gone, and
dae does not guess it back.

Two provable sources remain, and they are independent of each other:

1. **The Field cluster itself.** Each surviving `Field` object carries `name_`, `owner_`, and
   `host_offset_or_field_id_`. The last one is a **Smi**, and Smis are merged into the *Mint*
   cluster on serialization (`app_snapshot.cc`: "Smis are merged into the Mint cluster"), so its
   value is recoverable as the Mint's integer. That integer is the field's **word index**
   (word 0 = tags; first field is word 1, or word 2 in a generic class because word 1 holds the
   type arguments), hence `byte offset = word × word_size`.
2. **Accessor names.** An implicit getter/setter (`kind` 6/7) is named after its field — private
   ones as `get:_items`, public ones as the field name itself. Their body touches exactly one
   field, so "exactly one field-shaped access in the body" is a *provable* rule: the offset comes
   from the machine-code displacement, the name from the symbol. Two or more accesses (or any
   access whose shape cannot be read) means the function is dropped, not guessed at.
   (`Color.a`, `Paint._data`, `_HitTestResponse.hasPlatformView` come from this route.)

The two meet in the middle: on the 3.13 arm64 sample the accessor route independently reproduced
**40 of 41** Field-record entries with the *same* name *and* the same offset, and 39 of 39 on the
x64 build of the same SDK — **0 conflicts** anywhere. That agreement is the strongest evidence
available without source: one side reads the snapshot's own field table, the other reads machine
code plus a function symbol.

The offset chain was pinned down before either route was wired in, from four independent angles:

| What was checked | Evidence |
|---|---|
| `disp + 1 == word × word_size` | `_FutureListener.get_result` loads `[x1, #0x17]` (24 = word 3); `get_state` `[x2, #0x1f]` (word 4); `get_callback` `[x1, #0x27]` (word 5) — four fields, four exact hits |
| Word index = declaration order | `_Uri.path` is the 5th declared field of a non-generic class → mint 5 → `0x28`; the x64 build's `_Uri._initializeText` reads `[rax + 0x27]` for `path` |
| Generic classes shift by one word | `_FutureListener`/`_Future` are generic: `_nextListener` (declared first) is word 2, and the class's `fbm` (unboxed bitmap) is `0x10` = bit 4 = `state`, which *is* the field declared third |
| The tagged adjustment | `Error.get:_stackTrace` loads `[r1, #7]` and `Error._stackTrace_assign` stores to `[r1, #7]` — word 1 minus the 1-bit heap-object tag |

**How it shows up in the output.** A recovered name is attached as an attributed comment on the
memory access, never by rewriting the access:

```dart
x0 = mem((local_0), 0x17); /* _FutureListener.result (off 0x18) */  // 0x483fb4
```

The wording is deliberate: the comment asserts what the *owner class* has at that offset, and
says nothing about the base — dae does not track the base's type, and claiming `this.result`
without knowing the base is the receiver would be a fabrication. aotopsy can write `base.field`
because it runs whole-program type inference (`typetrack`); that is the route to closing
the remaining gap, and it is listed in the backlog.

Coverage, measured (all gates green, 0 `dart analyze` errors after the change):

| Corpus | Field records | From accessors (new) | Cross-source agreement | Conflicts | Annotated accesses |
|---|---|---|---|---|---|
| `sample_arm64` (arm64, 3.13) | 60 | 1 | 40 | 0 | 218 |
| `hello_3.13.0.aot` (x64, 3.13) | 60 | 0 | 39 | 0 | 152 |
| `T4_blank/libapp.so` (x64, 2.12.4) | 34 | 0 | 5 | 0 | 43 |
| Flutter `testing_app` (arm64, 3.13) | 366 | 1 | 83 | 0 | 438 |

Where it is silent, it is silent on purpose: an app class whose fields were dropped *and* whose
accessors were tree-shaken (e.g. `Favorites._items` in the Flutter sample) gets no name, because
neither the snapshot nor the symbols contain one. `dae fields <binary>` lists exactly what was
recovered and marks the source of each row (`rec` / `accessor`); `text/fields.txt` carries the
same table in the export.

`tests/field_names.rs` gates all of this: record/accessor floors per corpus, **zero conflicts**,
named probes at exact offsets, and — the part that catches fabrication — every `/* class.field
(off 0x..) */` in the emitted pseudocode must exist in the recovered table, with the offset
aligned to `word_size`.

## Two more traps, both found by adding a corpus

Adding an **arm64 ELF** artifact (`testing/variants/h212keep_linux_arm64.exe`, the one arch/container
combination the gate corpus did not have) dropped the structured rate from ~88% to **34%** and
produced 55 `dart analyze` errors. Three separate causes:

1. **No fall-through successor.** A conditional branch in the *last* block of a function has no
   successor after it — because the table's code size ends at the branch. The structurer treated
   "unknown fall-through" as "target out of range" and bailed, which cost 713 branches on that
   artifact. It now structures the target arm as `if (…) { … }` and ends the region: **34% → 89%**.
2. **Unbounded nesting.** `seq` recurses one level per diamond with no depth cap, so a 1608-block
   function could nest ~50 levels deep — the output became a staircase of `}` and Dart's parser
   reported `stack_overflow` (too many nested expressions). Capped at 10 levels; deeper regions
   are emitted straight-line with an honest `gotoLabel` and the `NOTE` header.
3. **A gate bug, not an output bug.** A pool string literal containing a brace (`BARRIER = "}" /* pp+0x2410 */`)
   broke the shape gate's brace counter. The terminator check had already been made
   string-literal-aware; the brace counter was not. Fixed on the gate side.

Also re-measured against aotopsy's numbers on the same file: dae 89% structured vs its 63% on the
corpora both tools read, 0 `dart analyze` errors vs ~70k — see [`COMPARISON.md`](COMPARISON.md).

## Known weak spots (the backlog)

**Done since that measurement -- identity-level naming from `CODE_REG`.** Dart's shared stubs load
their own `Code` object into the code register, so `ldr x24, [THR, #<field>]` inside a stub's *own
body* names it: `code_reg_stub_name` requires the field (looked up in that version's
`DartThread` layout, offset read from the instruction) to end in `_stub`, and emits
`<CamelCase(field)>_0x<addr>` -- e.g. `NullCastErrorSharedWithoutFpuRegsStub_0x3dc7b0`,
`LateInitializationErrorSharedWithoutFpuRegsStub_0x3dca38`, `DeoptimizeStub_0x3de1a0`,
`LazyDeoptFromThrowStub_0x3ddd40`. It is tried **before** `runtime_stub_name`, so the 13,316 sites
previously called `RuntimeCallStub_0x...` are upgraded to their real identities too (that shape
loads `stack_overflow_shared_without_fpu_regs_stub`). Measured: `material_3_demo` named direct calls
58,478 -> **69,796 of 86,825 (80.4%)**, up from 46.6% before this round of work; Reqable
28,440 -> **31,625**; Lark 30,567 -> **36,622**. `call_edges.txt` and `dart/` agree on all three.
All three still `dart analyze` clean with structured counts unchanged to the unit. Cross-version by
construction: Reqable (dart 3.3.4) resolves its names from the 3.3.4 header, not 3.13.0's.
Gate `code_reg_stub_names_trace_back_to_profile_and_instructions` works **backwards** from the
published name -- stem must exist as a `*_stub` field in that version's header, and the disassembled
body (cut at the first terminator) must contain `ldr CODE_REG, [THR, #<that field's offset>]`;
26 names re-derived on `sample_arm64`. Negative-tested: deleting the terminator cut fails it at once,
on exactly the predicted mis-attribution (`SlowTypeTestStub_0x4c47ac`, whose own body is one
instruction, `brk #0`).

**Next up -- the remaining half, with the rule that must be settled first.** A body whose only
identifying load is `ldr rN, [THR, #<*_entry_point>]` (91 addresses / 3,178 calls once scoped) proves
"this stub calls that runtime entry", **not** "this stub *is* that entry's stub". The discriminator
is multiplicity: `allocate_object_slow_entry_point` is loaded by **80 different addresses** -- 80
allocation stubs sharing one slow path, none of which is "the AllocateObjectSlow stub" -- while
`Throw_entry_point`, `Instanceof_entry_point`, `ReThrow_entry_point`, `DoubleToInteger_entry_point`,
`suspend_state_init_async_entry_point` and `OldMarkingStackBlockProcess_entry_point` are each loaded
by exactly one. So the rule is "name it only if exactly one address in the binary loads that field",
which yields ~11 addresses / ~3,000 calls. The other 238 addresses (13,851 calls) have no usable
`THR` load in their own body at all -- fat inlined allocators, dispatch stubs, type-test stubs.

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
4. Type recovery is partial: pool **values** are resolved and field names are attributed (both
   above), but the **base's type** is not tracked, so an access renders as
   `mem(base, disp) /* Class.field (off 0x..) */` rather than `base.field`. Closing that is the
   same job as aotopsy's `typetrack`: whole-program propagation from call sites, pool entries and
   the receiver slot. Locals and parameters are still `dynamic`.
5. **Call sites show no arguments**, so the registers a caller sets up look like dead stores:
   `x1 = NULL; x2 = 6; sub_0x2bb1d0();` is the remaining bulk of the `unused_local_variable`
   warnings (10,023 on a full Flutter build, 1,475 on the 160-line truth fixture). Rendering
   `sub_0x2bb1d0(x0, x1, x2)` looks trivial but is not honest yet: an argument register may have
   been written *before* an intervening call (Dart's stack-overflow stub preserves the receiver,
   so `x0` is still live at the next `bl`), and dae has no verified clobber list per ABI — with
   one it could compute real liveness and then show the arguments. Attempted and reverted for
   exactly this reason; the truth fixture caught it (`x0` was set 8 instructions and one call
   earlier).
6. The preamble is per file and mechanical; a smarter version would only declare what is used
   and give the helpers real signatures.
7. **Statement order does not follow address order** (measured 2026-09-28 by reading source against
   output): 21,826 sites = 2.74% of statements, touching 36.1% of functions. **Sorting by address
   would not fix it** -- a folded expression is only correct because it appears before the statement
   it folded. See "Known gaps" above.
8. **Return values are mostly not recovered**: bare `return;` is 95.6% of returns (17,238 vs 790).
   Not "never" -- both case branches of `classify` in the stress sample emit `return x0;` -- the
   statistic is dominated by void functions and epilogues.

## Adding a corpus

Drop an artifact into `dart/dart_samples/artifacts/` (scorecard picks up `.aot`, `.so`, `.exe`,
`.jit`, `.dylib`, `.bin`) or point `DAE_SCORECARD_EXTRA` at a colon-separated list of paths
(repo-external builds, e.g. a Flutter app bundle) and rerun the ignored test.