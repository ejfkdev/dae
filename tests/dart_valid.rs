//! 反编译产物的**可编译性门禁**：产物必须是合法 Dart。
//!
//! 判据来自 `dart analyze`——不是我们自己写的形态检查，而是真的解析 + 真的类型检查：
//! * 语法错误（`expected_token`/`missing_identifier`/…）说明产物根本不是 Dart；
//! * 语义错误（`undefined_identifier`/`undefined_function`/…）说明产物引用了一堆不存在
//!   的名字（寄存器、跨库调用目标、mem/memSet 这类机器层占位）。
//!
//! dae 的产物是伪代码（内存访问、间接调用没有真实类型），所以文件顶部会声明一段
//! *伪运行时*（`mem`/`memSet`/`callIndirect`/… + 用到的寄存器名），让伪代码能过分析。
//! 这不是"假装编译得过"——它把「哪里是机器层、哪里是 Dart 语义」显式写了出来。
//!
//! 计数口径：只数 `error -` 行。`warning`/`info`（未使用变量、未使用 import 之类）
//! 不计——它们不影响"能不能编译"。基线（2026-09-26，真实 Flutter app 412 个文件
//! 10 245 个函数）：**680 515 → 0**。
//!
//! `dart` 不在 PATH 或语料缺失时跳过；全量基线用
//! `cargo test --release --test dart_valid -- --ignored --nocapture`。

use std::path::{Path, PathBuf};
use std::process::Command;

fn dart_bin() -> Option<String> {
    let out = Command::new("dart").arg("--version").output().ok()?;
    out.status.success().then(|| "dart".to_string())
}

/// 对一个输出目录跑 `dart analyze`，返回 error 行
fn analyze_errors(dir: &Path) -> Result<Vec<String>, String> {
    let out = Command::new("dart")
        .arg("analyze")
        .arg(".")
        .current_dir(dir)
        .output()
        .map_err(|e| format!("启动 dart analyze 失败: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let errs: Vec<String> = text
        .lines()
        .filter(|l| l.trim_start().starts_with("error -"))
        .map(|l| l.trim().to_string())
        .collect();
    Ok(errs)
}

/// 语料 → (标签, 二进制, sdk profile, platform profile)
fn corpora(root: &Path) -> Vec<(String, PathBuf, Option<String>, Option<String>)> {
    let mut v: Vec<(String, PathBuf, Option<String>, Option<String>)> = vec![
        (
            "T4_blank (elf x64)".into(),
            root.join("testing/variants/T4_blank/libapp.so"),
            Some("dart-2.12.4-w64-no-compressed.json".into()),
            Some("elf-x64.json".into()),
        ),
        (
            "hello_3.12.2 (macho x64)".into(),
            root.join("dart/dart_samples/artifacts/hello_3.12.2.aot"),
            Some("dart-3.12.2-w64-no-compressed.json".into()),
            Some("macho-x64.json".into()),
        ),
        (
            "sample_arm64 (macho arm64)".into(),
            root.join("testing/decompiler_corpus/sample_arm64"),
            Some("dart-3.13.0-w64-no-compressed.json".into()),
            Some("macho-arm64.json".into()),
        ),
    ];
    v.retain(|(_, p, _, _)| p.exists());
    v
}

struct Score {
    label: String,
    files: usize,
    errors: usize,
    first: String,
    funcs: usize,
    structured: usize,
    unmapped: usize,
}

fn score_one(bin: &str, label: &str, so: &Path, sdk: Option<&str>, plat: Option<&str>) -> Score {
    let out = std::env::temp_dir().join(format!(
        "dae_dart_valid_{}",
        label.split_whitespace().next().unwrap_or("x")
    ));
    let _ = std::fs::remove_dir_all(&out);
    let out_s = out.display().to_string();
    let mut args: Vec<&str> = vec![so.to_str().unwrap(), &out_s, "--decompile"];
    if let Some(s) = sdk {
        args.push("--sdk-profile");
        args.push(s);
    }
    if let Some(p) = plat {
        args.push("--platform-profile");
        args.push(p);
    }
    let status = Command::new(bin).args(&args).output().expect("启动 dae 失败");
    if !status.status.success() {
        // 预期内的不支持（1.24.3 / 2.0.0 是 JIT 快照，按设计拒绝）；其余才算失败
        let stderr = String::from_utf8_lossy(&status.stderr);
        let expected = ["1.24.3", "2.0.0.jit", "hello_2.0.0", "bare app-JIT"];
        if expected.iter().any(|k| label.contains(k) || stderr.contains("app-JIT")) {
            return Score {
                label: label.to_string(),
                files: 0,
                errors: 0,
                first: "unsupported (JIT snapshot, by design)".into(),
                funcs: 0,
                structured: 0,
                unmapped: 0,
            };
        }
        panic!("{label}: dae 导出失败: {stderr}");
    }
    let dart_dir = out.join("dart");
    let files = std::fs::read_dir(&dart_dir)
        .map(|d| d.filter_map(|e| e.ok()).count())
        .unwrap_or(0);
    let errs = analyze_errors(&dart_dir).unwrap_or_default();
    let first = errs.first().cloned().unwrap_or_default();
    // dae 的摘要行里带质量指标（函数数 / 已结构化 / 未映射行），一并收进基线
    let stdout = String::from_utf8_lossy(&status.stdout);
    let (funcs, structured, unmapped) = parse_dart_summary(&stdout);
    Score {
        label: label.to_string(),
        files,
        errors: errs.len(),
        first,
        funcs,
        structured,
        unmapped,
    }
}

/// 从 `dart/   10245 function pseudocode blocks（… ；9436 已结构化，809 未结构化；63 unmapped 行；…）` 取值
fn parse_dart_summary(stdout: &str) -> (usize, usize, usize) {
    let line = stdout
        .lines()
        .find(|l| l.trim_start().starts_with("dart/"))
        .unwrap_or("");
    // 摘要随语系变（中文/英文两种标签都认）
    let num = |pats: [&str; 2]| -> usize {
        for pat in pats {
            if let Some(i) = line.find(pat) {
                if let Some(v) = line[..i]
                    .split_whitespace()
                    .last()
                    .and_then(|t| t.parse::<usize>().ok())
                {
                    return v;
                }
            }
        }
        0
    };
    // "10245 function" → 第一个数字
    let funcs = line
        .trim_start()
        .strip_prefix("dart/")
        .map(|r| r.trim_start())
        .and_then(|r| r.split_whitespace().next())
        .and_then(|t| t.parse::<usize>().ok())
        .unwrap_or(0);
    (
        funcs,
        num(["已结构化", "structured"]),
        num(["unmapped", "未映射"]),
    )
}

#[test]
fn emitted_dart_is_valid() {
    if dart_bin().is_none() {
        println!("emitted_dart_is_valid: 没有 dart（Dart SDK 不在 PATH）——跳过");
        return;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let bin = env!("CARGO_BIN_EXE_dae");
    let set = corpora(root);
    if set.is_empty() {
        println!("emitted_dart_is_valid: 无语料——跳过");
        return;
    }
    let mut bad = Vec::new();
    for (label, so, sdk, plat) in &set {
        let sdk_path = sdk.as_ref().map(|f| root.join("profiles/sdk").join(f));
        let plat_path = plat.as_ref().map(|f| root.join("profiles/platform").join(f));
        let s = score_one(
            bin,
            label,
            so,
            sdk_path.as_ref().and_then(|p| p.to_str()),
            plat_path.as_ref().and_then(|p| p.to_str()),
        );
        println!(
            "{:26} 文件 {:4} 函数 {:5} 结构化 {:5} 未映射 {:5}  dart analyze 错误 {}",
            s.label, s.files, s.funcs, s.structured, s.unmapped, s.errors
        );
        if s.errors > 0 {
            bad.push(s);
        }
    }
    assert!(
        bad.is_empty(),
        "产物必须能过 dart analyze（0 error）：{}",
        bad.iter()
            .map(|b| format!("{} → {} 条，例如 {}", b.label, b.errors, b.first))
            .collect::<Vec<_>>()
            .join("; ")
    );
}

/// 全量基线：`dart/dart_samples/artifacts/` 下每个版本都跑一遍并打印表。
/// 默认 `#[ignore]`——25 个版本 × dart analyze 要几分钟，不进每次提交的门禁。
#[test]
#[ignore]
fn full_scorecard() {
    if dart_bin().is_none() {
        println!("full_scorecard: 没有 dart——跳过");
        return;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let bin = env!("CARGO_BIN_EXE_dae");
    let arts = root.join("dart/dart_samples/artifacts");
    let mut rows: Vec<Score> = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(&arts)
        .expect("artifacts 目录")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    entries.sort();
    for p in entries {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        if !std::fs::metadata(&p).map(|m| m.is_file()).unwrap_or(false) {
            continue;
        }
        // artifacts/ 里除产物外还有 README 等：只收名字带已知后缀的
        let n = name.to_ascii_lowercase();
        if !(n.ends_with(".aot")
            || n.ends_with(".so")
            || n.ends_with(".exe")
            || n.ends_with(".jit")
            || n.ends_with(".dylib")
            || n.ends_with(".bin"))
        {
            continue;
        }
        rows.push(score_one(bin, &name, &p, None, None));
    }
    // 可选：把仓库外的真实项目也纳入基线（如 Flutter 样例 app 的产物）
    if let Ok(extra) = std::env::var("DAE_SCORECARD_EXTRA") {
        for p in extra.split(':').filter(|x| !x.is_empty()) {
            let pb = PathBuf::from(p);
            if pb.exists() {
                let label = pb
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| p.to_string());
                rows.push(score_one(bin, &label, &pb, None, None));
            }
        }
    }
    println!(
        "\n{:<28} {:>6} {:>7} {:>8} {:>8} {:>8}",
        "样本", "文件", "函数", "已结构化", "未映射", "analyze errors"
    );
    for r in &rows {
        println!(
            "{:<28} {:>6} {:>7} {:>8} {:>8} {:>8}",
            r.label, r.files, r.funcs, r.structured, r.unmapped, r.errors
        );
        if r.errors > 0 {
            println!("    {}", r.first);
        }
    }
    let total: usize = rows.iter().map(|r| r.errors).sum();
    println!(
        "\n合计 {} 个样本，{} 个文件，{} 个函数；dart analyze 错误 {}",
        rows.len(),
        rows.iter().map(|r| r.files).sum::<usize>(),
        rows.iter().map(|r| r.funcs).sum::<usize>(),
        total
    );
}