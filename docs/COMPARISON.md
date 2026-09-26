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

- **Dynamic field names.** aotopsy prints `local_16.values_14b94 = 0;` — a *field name* with its
  offset, from whole-program type inference (`typetrack`). dae prints `mem(local_16, 0x17)`. dae
  has the object-pool values (above) but not local/parameter types.
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

## Caveats

- **aotopsy is ELF-only** (`libapp.so`, "ELF parse"). The Flutter macOS/iOS `App.framework`
  (Mach-O) cannot be fed to it, so the arm64 comparison in this document could not be run;
  dae's arm64 numbers are in [`DECOMPILER.md`](DECOMPILER.md).
- A canonical arm64 comparison wants an **Android `libapp.so`** (`flutter build apk --release`).
  That needs the Android SDK/NDK and network access to Maven; neither was available here.
- aotopsy's extra *signals* (behavioral classification, crypto/network keywords, Frida export,
  SARIF, dispatch-table recovery, evidence/confidence records) were not compared: they are
  capabilities dae does not attempt rather than differences in the shared ones.