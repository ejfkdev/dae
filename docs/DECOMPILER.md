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
| hello_3.13.0 | 15 | 1174 | 1047 (89%) | 166 | 0 |
| hello_3.12.2 | 15 | 1176 | 1049 (89%) | 166 | 0 |
| hello_3.14b | 15 | 1161 | 1035 (89%) | 166 | 0 |
| hello_3.11.6 | 15 | 1133 | 1015 (89%) | 149 | 0 |
| hello_3.10.9 | 14 | 1104 | 987 (89%) | 149 | 0 |
| hello_3.9.4 | 14 | 1106 | 991 (89%) | 155 | 0 |
| hello_3.8.3 | 14 | 1103 | 988 (89%) | 155 | 0 |
| hello_3.7.2 | 14 | 1111 | 994 (89%) | 155 | 0 |
| hello_3.6.1 | 14 | 1108 | 1002 (90%) | 1 | 0 |
| hello_3.5.0 | 13 | 1111 | 1005 (90%) | 1 | 0 |
| hello_3.4.0 | 13 | 1138 | 1034 (90%) | 1 | 0 |
| hello_3.3.4 (appended ELF blob) | 14 | 1130 | 1026 (90%) | 1 | 0 |
| hello_3.2.0 | 14 | 1143 | 1026 (89%) | 152 | 0 |
| hello_3.0.0 | 15 | 1207 | 1088 (90%) | 33 | 0 |
| hello_2.19.6 | 2 | 229 | 212 (92%) | 4 | 0 |
| hello_2.18.1 | 2 | 254 | 233 (91%) | 1 | 0 |
| hello_2.17.0 | 14 | 1231 | 1112 (90%) | 23 | 0 |
| hello_2.16.2 | 1 | 1086 | 993 (91%) | 20 | 0 |
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
5. The preamble is per file and mechanical; a smarter version would only declare what is used
   and give the helpers real signatures.

## Adding a corpus

Drop an artifact into `dart/dart_samples/artifacts/` (scorecard picks up `.aot`, `.so`, `.exe`,
`.jit`, `.dylib`, `.bin`) or point `DAE_SCORECARD_EXTRA` at a colon-separated list of paths
(repo-external builds, e.g. a Flutter app bundle) and rerun the ignored test.