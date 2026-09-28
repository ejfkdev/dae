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
DAE_REQUIRE_GATES=1 cargo test --release           # turn every "dependency missing, skipping" into a failure
```

The last one matters more than it looks. Five of the six gate files consume corpora that are
gitignored (`testing/`, `dart/dart_samples/`), and they skip themselves when those are absent while
`cargo test` swallows the notice — a fresh clone therefore reports a green suite having measured
almost nothing. `DAE_REQUIRE_GATES=1` makes any such skip fail, which is the only way to
distinguish "the gates passed" from "the gates never ran".

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