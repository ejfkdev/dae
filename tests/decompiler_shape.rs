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

/// 结构化率下限（当前 T4_blank 实测约 0.61，直线函数也算结构化）
const STRUCTURED_FLOOR: f64 = 0.50;

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
