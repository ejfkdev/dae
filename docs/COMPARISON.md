# dae vs aotopsy: measured comparison

Both tools parse Dart AOT snapshots and emit pseudocode. This is what happens when they are
pointed at **the same file** and judged by the same rules.

Reproduce (script lives in `testing/`, not committed):

```bash
python3 testing/compare_aotopsy.py <libapp.so> [out_root]
```

The script runs both tools with their own defaults, then measures: address coverage, name
agreement against the ELF `.symtab` (the external ground truth), `dart analyze` errors, how many
functions still carry a `goto`, how many object-pool literals got inlined, and wall time.

## The rules, so neither tool is favoured

- **Same input file.** Both read the same `libapp.so`; nothing is pre-processed for one of them.
- **Names compared after one uniform normalization.** Library-hash suffixes (`@0150898`),
  trailing `_<digits>` code indices, all-digit tokens and the dialect words
  `Precompiled_` / `init` / `new` are stripped from both sides; then every remaining token of the
  *ground truth* name must appear in the tool's name. Each tool additionally reports ~90% under
  **its own** dialect-aware rule (dae's `tests/ground_truth.rs` gate: 90.6%; aotopsy's README:
  90.2%) — the uniform rule here lands lower for both, which is expected and fair.
- **Validity is `dart analyze`**, errors only, split into syntax-class and semantic-class codes.
  aotopsy's README claims "100% valid Dart" measured by "every emitted pseudocode function parses"
  (`TestDecompileQualityCorpus`) — that is a *parse* check, so the semantic column below is not
  a contradiction of its claim, it is a different question: does the output also *analyze*.
- aotopsy has no CLI switch for structured output, so "structured" is measured the same way for
  both: a function counts as unstructured if its body (comments stripped) contains a goto —
  `gotoLabel(0x..)` for dae, `goto block_N;` / `label:` for aotopsy.

## Results (three x64 ELF corpora, same files)

| | T4_blank | | hello_2.15.0 | | H_minimal_compact | |
|---|---|---|---|---|---|---|
| | **dae** | aotopsy | **dae** | aotopsy | **dae** | aotopsy |
| functions with an address | 1434 | 1434 | 1418 | 1418 | 1434 | 1434 |
| …of those in `.symtab` | 1434 | 1434 | 1418 | 1418 | 1434 | 1434 |
| name agreement (uniform rule) | 83.8% | 87.1% | 81.0% | 84.6% | 83.5% | 87.2% |
| `dart analyze` syntax errors | **0** | 5233 | **0** | 5380 | **0** | 5233 |
| `dart analyze` semantic errors | **0** | 65109 | **0** | 62720 | **0** | 65081 |
| functions with a `goto` | **12.2%** | 64.3% | **9.3%** | 63.4% | **12.2%** | 64.3% |
| inlined pool literals | 318 | 298 | 502 | 295 | 315 | 295 |
| wall time | **0.38s** | 2.90s | **0.33s** | 2.61s | **0.39s** | 2.87s |

Function counts are equal because of a fix this comparison produced (below); the earlier state was
1258 vs 1434.

## Where dae is ahead

- **The output compiles.** ~70k `dart analyze` errors per file for aotopsy vs 0 for dae: 5.2k
  syntax-class (undeclared registers/`goto` targets that do not parse) and 65k semantic-class
  (undeclared identifiers/functions). dae emits a per-file pseudo-runtime preamble and rewrites
  machine syntax, which is what closes this gap — see [`DECOMPILER.md`](DECOMPILER.md).
- **Control flow is structured.** 9–12% of dae's functions keep a `goto` vs 63–64% of aotopsy's.
  aotopsy's own output says so in place: `goto block_2;` with `block_2:;` labels, plus
  `// --- code omitted by the structured walk, shown verbatim ---`.
- **Speed.** ~7× faster on the same file (0.4s vs 2.9s).
- **Pool constants.** dae inlines more resolved literals here (318 vs 298, 502 vs 295); on the
  Flutter macOS app it resolves 1922.

## Where aotopsy is ahead

- **Field accesses are rewritten, not annotated.** aotopsy prints
  `local_16.values_14b94 = 0;` — the base, a dot, the field name. dae now recovers the same names
  by the same *source* (it reads `MintValues[HostOffset] × wordSize`, exactly as aotopsy's
  `class_layouts.go` does, and adds implicit-accessor names on top), but attaches them as an
  attributed comment: `mem(local_16, 0x17) /* _FutureListener.result (off 0x18) */`. Writing
  `local_16.result` requires knowing the base's **type**, which aotopsy gets from whole-program
  inference (`typetrack`) and dae does not do yet — asserting it without that would be a
  fabrication. So: same names, different rendering, and dae's is the honest half.
- **Type-testing stub names.** aotopsy names all 176 unclaimed table entries
  (`TypeTestingStub__GrowableList@0150898`); dae names the 88 allocation stubs provably and leaves
  the 88 type-testing stubs as bare addresses. That is the entire ~3.5pp naming gap in the table.
  The correct route is aotopsy's: the object pool's `Type` entries carry a `type_test_stub_` field
  pointing at the stub, so (type → stub address) is *provable* where a pattern match is not.
- **Per-function files under class directories** (1603 small files) versus dae's per-library files
  (17). A navigation preference, not a correctness difference — but it is why aotopsy's
  "file count" looks larger.

## What the comparison changed in dae

1. **Coverage.** aotopsy found 176 functions dae did not list. They are the instruction table's
   *stub* segment — entries with no Code object. dae now lists them in a new
   `text/stubs.txt` (entry, size, decoded name when provable), so coverage is equal, and the
   decoded allocation-stub names are used in the pseudocode:
   `call sub_0xfb68() /* 0xfb68 */` became `call AllocationStub_UnsupportedError() /* 0xfb68 */`.
2. **A fabrication trap, caught by ground truth.** Extending the decoder to type-testing stubs
   looked easy — same shape (materialize a class id, then compare) — but the id being compared is a
   *bare* cid while allocation stubs materialize the *tagged* word, and the `mov r8d, 0x31`
   (49 = `_Smi`) in front is just the Smi-branch initial value. The naive version named 12 stubs
   and **4 of them were wrong** (two `AllocateMint*Stub` iso stubs and `AllocateContextStub` got
   type-testing names, one became `_Smi`). Comparing against `.symtab` caught it immediately; the
   code was reverted to provable-only. Current state: 88/88 agree with ground truth, 0 fabricated.
3. **Two comments were wrong and are now correct.** `entry_for`'s "stub (idx < first_entry)
   returns None" described `code_base_ref` as if it marked a prefix of stubs; on these corpora
   `first_entry` is 0 and the 167 skipped Code objects are the stub segment identified by
   `ci <= code_base_ref`.

## 2026-09-26 re-measurement: real Flutter apps, and where the corpus was misleading

The table above was measured on x64 ELF corpora. Re-measuring against **real Flutter applications**
(the user's local APK set plus a commercial macOS app) moves the conclusion in one important way.

### Mobile/Android Flutter builds: FIXED (2026-09-26, later the same day)

The gap described in the next section was closed the same day it was measured. dae now ships
**compressed-pointer profile variants** and selects them automatically from the snapshot's own
features string, so no flag is needed:

```
dae /tmp/android/libapp.so out/          # auto-detects dart/3.3.4 + w32-compressed variant
```

| App | SDK | dae now | aotopsy (same file) |
|---|---|---|---|
| Reqable (Android) | 3.3.4 | 57,960 table entries, 496 libs, 1,141 classes, **0 warnings** | 57,960 functions / 8,216 classes |
| ChatGLM | 3.11.6 | 30,782 entries, 1,211 libs, 4,603 classes | 30,782 / 5,501 |
| 学信网 (CHSI) | 3.7.2 | 19,752 entries, 875 libs, 3,256 classes | 19,752 / 3,819 |
| 飞书 Lark | 3.6.1 | parses, still drifts before the object pool (open) | 79,327 / 12,929 |
| 微博 Weibo | 2.19.6 | same class of residue (open) | 22,623 / 4,232 |

Reqable's Android build also decompiles: **1,707 functions, 95.5% fully structured, 0
`dart analyze` errors**, and 227 field names recovered from accessor symbols — 144 of them agree
exactly (name + byte offset) with aotopsy's class layouts, with 0 real conflicts (`type` vs its
synthetic `type_arguments_field` is a naming choice, not a disagreement).

The table-entry counts matching aotopsy **exactly** on three separate apps is the strongest signal
available without symbols: two independent implementations agree on how many functions the binary
contains.

What the fix required (all in `src/engine` + `tools/sdk2profile.py`, no rewrite):

1. **No ROData clusters in compressed builds** — `NewClusterForClass` wraps the whole
   `RODataSerializationCluster` class in `#if !defined(DART_COMPRESSED_POINTERS)` (a memory image
   cannot be guaranteed inside the 4 GB region compressed pointers can address). Strings therefore
   travel as an ordinary filled cluster: alloc writes `(length<<1)|two_byte` per object, fill
   repeats it followed by the raw bytes. `PcDescriptors` / `CodeSourceMap` / `CompressedStackMaps`
   become ordinary clusters too (`uvarint(len) + len bytes`).
2. **Instance field slots are pointer-width units** — the fill walks `next_field_offset = nfo <<
   kCompressedWordSizeLog2` with a 4-byte stride, and fields start after an 8-byte header, so the
   slot count is `nfo − 2` rather than `nfo − 1`. Getting this wrong cost one extra slot per
   instance and drifted the fill stream by 4.8 KB (the object pool's length then read as garbage).
3. **The VM isolate does not write the string cluster's canonical-set trailer** —
   `StringSerializationCluster(is_canonical, cluster_represents_canonical_set && !vm_)`, while the
   *rodata* string cluster (uncompressed builds) has no such exclusion. Both rules now apply to
   their own cluster kind.
4. **The data image still aligns to 64** in compressed builds (the instructions table lives there),
   and the table itself is read at `data_image + rodata_offset + 16` (it is the payload of a
   OneByteString).

### The gap as first measured (2026-09-26, before the fix)

Eight Flutter APKs were extracted (`lib/arm64-v8a/libapp.so`) and probed with both tools:

| App | SDK (from the snapshot's own hash) | aotopsy | dae |
|---|---|---|---|
| Reqable | 3.3.4 | 57,960 functions / 8,216 classes | drift, refused |
| Lark | 3.6.1 | 79,327 / 12,929 | drift, refused |
| ChatGLM | 3.11.6 | 30,782 / 5,501 | drift, refused |
| CHSI | 3.7.2 | 19,752 / 3,819 | drift, refused |
| Weibo | 2.19.6 | 22,623 / 4,232 | drift, refused |
| WeChat (rimet) | 2.15.0 | not modeled | drift |
| 同花顺 | 2.7.2 | not modeled | drift |

The cause is in the artifacts' own feature strings, which dae already reads past to find the header:

```
desktop build: product no-code_comments no-dwarf_stack_traces_mode ... macos     no-compressed-pointers
Android build: product no-code_comments    dwarf_stack_traces_mode ... android compressed-pointers
```

Two build flags change the snapshot layout, and **all 26 shipped dae profiles are uncompressed desktop
builds**:

- `compressed-pointers` — pointer size 4 instead of 8 (aotopsy reports `ptr_size: 4` for every one of
  these), so every object layout, alignment and slab the parse walks is different;
- `dwarf_stack_traces_mode` — the Code cluster pushes two fewer refs
  (`app_snapshot.cc`, 3.3.4: `if (!FLAG_precompiled_mode || !FLAG_dwarf_stack_traces_mode) { push
  inlined_id_to_function_; push code_source_map_; }`), so the fill stream after it is misaligned.

Both are *profile* differences — the parsing engine itself is fine — so the fix is a profile-variant
job, not a rewrite: `tools/sdk2profile.py` already takes `--word-size 4 --compressed`, the vendored
SDK sources for 24 versions are in the workspace, and the `dwarf_stack_traces_mode` variant needs the
same flag-aware derivation for `code_refs`. Detection can be exact rather than heuristic: dae already
parses the features string, so the profile variant can be selected from `compressed-pointers` /
`dwarf_stack_traces_mode` directly.

Two robustness bugs surfaced *because* of these failing parses, and are fixed:

- The nested-value renderer recursed without a bound, so a garbage parse (self-referential arrays)
  **crashed the process with a stack overflow** in an export thread. Bounded at 8 levels now.
- A drifted parse printed warnings but still wrote artifacts and exited 0. It now prints a FATAL
  line, writes `PARSE_DRIFT.txt` into the output directory, and exits non-zero — the raw dumps
  (`text/strings.txt`, `text/pp.txt`) stay on disk because they are still readable by hand.

Note on version reporting: for Reqable, aotopsy prints `dart: 3.3.0` while dae prints `dart/3.3.4`,
which is the version recorded by the snapshot's own build hash (`ee1eb666c76a5cb7746faf39d0b97547`,
the same hash in that app's macOS build — confirmed by a blutter run on it). aotopsy's number is its
nearest modeled version; dae's is the artifact's own claim.

### A commercial macOS app (dae-only: aotopsy cannot read Mach-O)

`/Applications/Reqable.app` (26 MB App.framework binary, obfuscated Dart, `dwarf_stack_traces_mode`):

| | dae |
|---|---|
| libraries / classes | 564 / 1,285 |
| named fields | 2,105 |
| functions decompiled | 1,808 (1,716 fully structured = **94.9%**) |
| unmapped instruction lines | 1 |
| `dart analyze` errors | **0** |
| `text/pp.txt`, `text/objs.txt` vs blutter's output for the same binary | **byte-identical** |
| wall time | 118 s |

aotopsy on the same file: `error: elfx: not an ELF file: bad magic number [202 254 186 190]` — its
loader is ELF-only, so macOS/iOS/Windows Flutter targets are dae-only territory. (The `dart analyze`
count was 1 before this run: a pool string `"$IsolateException"` was emitted unescaped, which Dart
reads as interpolation. Fixed — `$` is now escaped like the other metacharacters, with a unit test.)

### Field names, head-to-head (T4_blank, 2.12.4)

| | dae | aotopsy |
|---|---|---|
| named (class, offset) pairs | 34 | 149 |
| …of which synthetic | 0 | 107 (`type_arguments_field` for the type-args slot) + ~10 more |

- **32 pairs agree exactly on name and offset, 0 conflicts** — two independent implementations
  reading the same snapshot fact (`MintValues[host_offset] × word_size`).
- dae has 2 names aotopsy's layout table does not carry (its accessor-symbol route).
- aotopsy still leads on *rendering*: it rewrites the access to `base.field` using whole-program type
  inference, while dae attributes the name as a comment and keeps `mem(base, disp)`.

## Caveats

- **aotopsy is ELF-only** (`libapp.so`, "ELF parse"). The Flutter macOS/iOS `App.framework`
  (Mach-O) cannot be fed to it, so the arm64 comparison in this document could not be run;
  dae's arm64 numbers are in [`DECOMPILER.md`](DECOMPILER.md).
- A canonical arm64 comparison wants an **Android `libapp.so`** (`flutter build apk --release`).
  That needs the Android SDK/NDK and network access to Maven; neither was available here.
- aotopsy's extra *signals* (behavioral classification, crypto/network keywords, Frida export,
  SARIF, dispatch-table recovery, evidence/confidence records) were not compared: they are
  capabilities dae does not attempt rather than differences in the shared ones.