//! 反编译产物形态门禁。
//!
//! 两件事，都是硬判据：
//! 1. **结构完整**：每个发射出来的 .dart 文件花括号配平，函数体内每行以 `;`/`{`/`}` 结束
//!    （注释行除外）。花括号配不平意味着结构化把某个分支吞了——这是静默丢代码，最糟的失败模式。
//! 2. **结构化率**：直线 + if/else + 循环 覆盖的函数占比有下限。未结构化的函数会显式带
//!    `goto`（Dart 没有 goto，属伪代码），故这个比率就是"离可编译 Dart 还有多远"的度量。
//!
//! 语料缺失时跳过；语料在但一个函数都反编译不出来视为失败。

use dae::analyzer::Analyzer;
use dae::profile::{parse_platform, parse_sdk, PlatformProfile, SdkProfile};
use std::path::Path;

/// 从操作数文本里取第一个 `0x...`（arm64 写作 `bl #0x1234`、x64 写作 `call 0x1234`）。
fn first_hex(s: &str) -> Option<u64> {
    let i = s.find("0x")?;
    let hex: String = s[i + 2..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    if hex.is_empty() {
        return None;
    }
    u64::from_str_radix(&hex, 16).ok()
}

/// 结构化率下限（直线函数也算结构化）。
///
/// 这个数字随 lift 覆盖面变化，**不是越高越好**：lift 认不出的分支（曾经的 cbz/tbz/csel）
/// 会退化成 `Other`，块里就没有分支，函数看起来"直线所以结构化"，但产物是**缺了分支的**。
/// 目前 lift 已覆盖条件跳转的全部常见形态，结构化器也补了 join==区域终点、if-return
/// 两类形状，故实测：T4_blank(x64) 87%、hello_3.12.2(x64) 89%、真实 Flutter app 92%、
/// 最小 arm64 样本 76%。门禁取 0.70（对最小样本留余量）。
const STRUCTURED_FLOOR: f64 = 0.70;

/// 地址可信度下限——**这条门禁是补出来的教训**。
///
/// 曾经 Mach-O 的 appended 快照（`dart compile exe` / 部分 Flutter 产物）拿不到指令段
/// 基准，`instr_off=0`，于是 pc_offset 被当成文件偏移：反汇编的是**别的代码**，
/// 而函数名/结构化率这些指标全都正常（名字来自 Code 对象，与地址无关）。
/// 只有「地址自洽性」能暴露它：
/// * 函数**入口**应是序言（arm64 `stp`/`sub sp`、x64 `push rbp`/`mov`）；
/// * 函数**末尾**应是终止符（`ret`/`b`/`jmp`/`brk`）或填充（x64 `int3` 对齐填充）；
/// * 直接调用的目标应落在函数入口上（Dart AOT 的 `bl` 目标 = Code 入口）。
///
/// 修复前：末指令为终止符 1%、调用命中入口 1%。修复后：82–96% / 29–34%。
const TERMINATOR_FLOOR: f64 = 0.60;
const CALL_HIT_FLOOR: f64 = 0.20;

#[cfg(feature = "asm")]
#[test]
fn decompiler_shape() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let corpus = [
        (
            "T4_blank (x64)",
            root.join("testing/variants/T4_blank/libapp.so"),
            "dart-2.12.4-w64-no-compressed.json",
            "elf-x64.json",
        ),
        (
            "hello_3.12.2 (macho x64)",
            root.join("dart/dart_samples/artifacts/hello_3.12.2.aot"),
            "dart-3.12.2-w64-no-compressed.json",
            "macho-x64.json",
        ),
        // arm64 且是 append 到可执行文件尾部的快照（无符号表，靠 LC_NOTE 定位指令段）
        (
            "sample_arm64 (macho arm64)",
            root.join("testing/decompiler_corpus/sample_arm64"),
            "dart-3.13.0-w64-no-compressed.json",
            "macho-arm64.json",
        ),
    ];
    let mut ran = 0usize;
    for (label, so, sdk_name, plat_name) in corpus {
        if !so.exists() {
            continue;
        }
        let data = std::fs::read(&so).expect("读样本");
        let sdk_src = std::fs::read_to_string(root.join("profiles/sdk").join(sdk_name)).unwrap();
        let plat_src = std::fs::read_to_string(root.join("profiles/platform").join(plat_name)).unwrap();
        let sdk: SdkProfile = parse_sdk(&sdk_src).unwrap();
        let plat: PlatformProfile = parse_platform(&plat_src).unwrap();
        let (vm_off, iso_off, instr_off) = dae::platform::locate_snapshots(&data, &plat).unwrap().0;
        let a = Analyzer::new_located(&data, &sdk, &plat, (vm_off, iso_off, instr_off), false).unwrap();
        let libs = a.build_functions(true);

        let out = std::env::temp_dir().join(format!("dae_dec_gate_{ran}"));
        let _ = std::fs::remove_dir_all(&out);
        let st = dae::decompiler::write(&a, &libs, &out).expect("反编译导出");
        ran += 1;
        assert!(st.funcs > 0, "{label}: 一个函数都没反编译出来");

        // 花括号配平 + 行形态
        let mut files = 0usize;
        for ent in std::fs::read_dir(out.join("dart")).unwrap() {
            let p = ent.unwrap().path();
            if p.extension().and_then(|s| s.to_str()) != Some("dart") {
                continue;
            }
            files += 1;
            let src = std::fs::read_to_string(&p).unwrap();
            // 产物必须**零非 ASCII**（仓库口径：导出物一律英文，便于跨环境比对与阅读）
            if let Some(pos) = src.find(|c: char| !c.is_ascii()) {
                let ctx = &src[pos.saturating_sub(40)..(pos + 40).min(src.len())];
                panic!("{}: 产物含非 ASCII 字符 …{ctx}…", p.display());
            }
            let mut depth: i64 = 0;
            let mut in_fn = false;
            for (ln, line) in src.lines().enumerate() {
                let t = line.trim();
                if t.starts_with("//") || t.is_empty() {
                    continue;
                }
                if t.starts_with("dynamic ") && t.ends_with('{') {
                    in_fn = true;
                }
                depth += t.matches('{').count() as i64;
                depth -= t.matches('}').count() as i64;
                assert!(depth >= 0, "{}:{} 花括号提前闭合", p.display(), ln + 1);
                // 行尾 `// 0x..` 是地址注释，判形态前先剥掉
                let code = t.split("//").next().unwrap_or("").trim_end();
                if in_fn
                    && depth > 0
                    && !code.is_empty()
                    && !code.ends_with(';')
                    && !code.ends_with('{')
                    && !code.ends_with('}')
                {
                    panic!("{}:{} 函数体内语句没有正常结束: {t}", p.display(), ln + 1);
                }
            }
            assert_eq!(depth, 0, "{} 花括号不配平（丢了分支？）", p.display());
        }
        assert!(files > 0, "{label}: 没产出 .dart 文件");

        let structured = st.structured as f64 / (st.structured + st.fallback).max(1) as f64;
        println!(
            "{label:20} 文件 {files:3}  函数 {:5}  基本块 {:6}  语句 {:7}  结构化率 {:.1}%",
            st.funcs, st.blocks, st.stmts, structured * 100.0
        );
        assert!(
            structured >= STRUCTURED_FLOOR,
            "{label}: 结构化率 {structured:.3} 低于门禁 {STRUCTURED_FLOOR}"
        );

        // ---- 地址自洽性 ----
        let mut entries: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for (_lib, cls_map) in &libs {
            for (_cls, funcs) in cls_map {
                for f in funcs {
                    if f.ep != 0 {
                        entries.insert(f.ep);
                    }
                }
            }
        }
        // 指令表里所有入口也算（含没有名字的 stub/闭包）
        for idx in 0..a.pc_offsets.len() {
            if let Some((ep, _)) = a.code_range(idx) {
                entries.insert(ep);
            }
        }
        let (mut n_fn, mut n_term, mut n_call, mut n_hit) = (0usize, 0usize, 0usize, 0usize);
        for ent in std::fs::read_dir(out.join("dart")).unwrap() {
            let p = ent.unwrap().path();
            if p.extension().and_then(|s| s.to_str()) != Some("dart") {
                continue;
            }
            let src = std::fs::read_to_string(&p).unwrap();
            let lines: Vec<&str> = src.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if !line.starts_with("// raw disassembly:") {
                    continue;
                }
                // 反汇编块：`//  0x4080: stp FP, LR, [SP, #-0x10]!` → (助记符, 操作数)
                let mut ins: Vec<(&str, &str)> = Vec::new();
                let mut j = i + 1;
                while j < lines.len() && lines[j].starts_with("//  0x") {
                    let rest = lines[j].split_once(':').map(|x| x.1).unwrap_or("");
                    let rest = rest.trim();
                    let mn = rest.split_whitespace().next().unwrap_or("");
                    let ops = rest[mn.len()..].trim();
                    ins.push((mn, ops));
                    j += 1;
                }
                if ins.is_empty() {
                    continue;
                }
                n_fn += 1;
                // x64 的 int3 是函数末尾的对齐填充（0xCC），与终止符等价
                if matches!(
                    ins[ins.len() - 1].0,
                    "ret" | "retq" | "b" | "jmp" | "brk" | "ud2" | "int3"
                ) {
                    n_term += 1;
                }
                for (mn, ops) in &ins {
                    if !matches!(*mn, "bl" | "call" | "callq") {
                        continue;
                    }
                    if let Some(v) = first_hex(ops) {
                        n_call += 1;
                        if entries.contains(&v) {
                            n_hit += 1;
                        }
                    }
                }
            }
        }
        let term_rate = n_term as f64 / n_fn.max(1) as f64;
        let hit_rate = n_hit as f64 / n_call.max(1) as f64;
        println!(
            "{label:20} 末指令终止符 {:.1}%  调用命中入口 {:.1}%（{n_hit}/{n_call}）",
            term_rate * 100.0,
            hit_rate * 100.0
        );
        assert!(
            term_rate >= TERMINATOR_FLOOR,
            "{label}: 只有 {:.1}% 的函数以终止符/填充结束（门禁 {:.0}%）——\
             代码范围很可能整体错位（历史故障：Mach-O appended 快照的 instr_off 缺失）",
            term_rate * 100.0,
            TERMINATOR_FLOOR * 100.0
        );
        assert!(
            hit_rate >= CALL_HIT_FLOOR,
            "{label}: 直接调用只有 {:.1}% 命中函数入口（门禁 {:.0}%）——地址与函数表不一致",
            hit_rate * 100.0,
            CALL_HIT_FLOOR * 100.0
        );
    }
    if ran == 0 {
        println!("decompiler_shape: 无语料——跳过");
    }
}
/// 源码对照门禁：拿 `testing/decompiler_corpus/` 里自己编的样本，
/// **源码里声明的每个函数/方法都必须出现在伪代码里**（方法按 `类_方法` 命名）。
///
/// 这是唯一能验"反编译语义"的判据——`.symtab` 只能验命名与地址。
/// 语料没编（`build.sh` 未跑）时跳过。
#[cfg(feature = "asm")]
#[test]
fn source_anchors() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = root.join("testing/decompiler_corpus");
    let exe = dir.join("sample_arm64");
    let src = dir.join("sample.dart");
    if !exe.exists() || !src.exists() {
        println!("source_anchors: 无语料（先跑 testing/decompiler_corpus/build.sh）——跳过");
        return;
    }
    let text = std::fs::read_to_string(&src).unwrap();
    // 极简声明提取：`<ret?> name( ... ) {` 形式；跳过控制流/调用语句
    let skip = [
        "if", "for", "while", "switch", "catch", "return", "print", "throw", "assert", "else",
    ];
    let mut want: Vec<String> = Vec::new();
    let mut cur_class = String::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("//") || t.is_empty() {
            continue;
        }
        // 只有**顶格**的 `}` 才是类体结束；方法体的 `}` 是缩进的，不能清类名
        if line.starts_with('}') && !line.starts_with("  ") {
            cur_class.clear();
            continue;
        }
        if let Some(i) = t.find("class ") {
            let rest = &t[i + 6..];
            cur_class = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            continue;
        }
        if !t.ends_with('{') || !t.contains('(') {
            continue;
        }
        let head = t.split('(').next().unwrap_or("").trim();
        let name: String = head
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        if name.is_empty() || skip.contains(&name.as_str()) {
            continue;
        }
        want.push(if cur_class.is_empty() {
            name
        } else {
            format!("{cur_class}_{name}")
        });
    }
    if want.is_empty() {
        println!("source_anchors: 源码里没提出声明——跳过");
        return;
    }

    // 反编译该产物
    let plat_src = std::fs::read_to_string(root.join("profiles/platform/macho-arm64.json")).unwrap();
    let plat: PlatformProfile = parse_platform(&plat_src).unwrap();
    let data = std::fs::read(&exe).unwrap();
    // 版本用探测（dart compile 的产物没有可配的 profile 参数）
    let s = dae::locale::messages(dae::locale::Lang::En);
    let (offs, _) = dae::platform::locate_snapshots(&data, &plat).unwrap();
    let sdk = dae::profile::detect::detect_or_default(&data, offs, &s);
    let a = Analyzer::new_located(&data, &sdk, &plat, offs, false).unwrap();
    let libs = a.build_functions(true);
    let out = std::env::temp_dir().join("dae_src_anchor");
    let _ = std::fs::remove_dir_all(&out);
    dae::decompiler::write(&a, &libs, &out).expect("反编译导出");

    let mut all = String::new();
    for ent in std::fs::read_dir(out.join("dart")).unwrap() {
        all.push_str(&std::fs::read_to_string(ent.unwrap().path()).unwrap());
    }
    // dae 实际导出的函数名集合（编译器可能内联/消除小函数，那些本来就没有独立 Code）
    let mut exposed: Vec<String> = Vec::new();
    for (_lib, cls_map) in &libs {
        for (cls, funcs) in cls_map {
            for f in funcs {
                exposed.push(if cls.is_empty() {
                    f.mangled.clone()
                } else {
                    format!("{cls}_{}", f.mangled)
                });
            }
        }
    }
    let mut missing = Vec::new();
    let mut inlined = Vec::new();
    for w in &want {
        if !all.contains(&format!("dynamic {w}(")) {
            if exposed.contains(w) {
                missing.push(w.clone());
            } else {
                inlined.push(w.clone()); // 编译器内联/消除，快照里本就没有独立函数
            }
        }
    }
    println!(
        "source_anchors: 源码声明 {} 个；伪代码缺失 {} 个{:?}；快照里不存在（已内联/消除）{} 个{:?}",
        want.len(),
        missing.len(),
        missing,
        inlined.len(),
        inlined
    );
    assert!(
        missing.is_empty(),
        "dae 已导出的函数在伪代码里找不到: {missing:?}"
    );
    // 源码里有 if/else、for、while，产物至少要出现 if 与 while 结构
    assert!(all.contains("if ("), "产物里没有任何 if 结构");
    assert!(all.contains("while ("), "产物里没有任何 while 结构");
}
