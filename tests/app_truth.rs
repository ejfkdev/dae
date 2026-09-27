//! **真实 Flutter 应用的源码真值门禁。**
//!
//! 与 `tests/source_truth.rs` 互补：那个自己现编一个 160 行的 fixture，规模小但完全可控；
//! 这个拿**真实应用**的源码对拍，规模大两个数量级（material_3_demo 5 107 行 / animations 2 108 行），
//! 因此能抓到 fixture 抓不到的东西——库到文件的映射、被 tree-shake 之后还剩什么、
//! 十万条语句量级下产物是否仍然合法。
//!
//! 语料在仓库外（flutter-samples 检出 + 本地构建产物），用 `DAE_DEMO_ROOT` 指定根目录，
//! 默认取仓库同级的 `flutter-samples`。缺失时按本仓库统一口径处理：默认跳过并打印，
//! `DAE_REQUIRE_GATES=1` 下直接失败（见 [[skip_or_fail]]）。
//!
//! 实测基线（2026-09-27，Flutter 3.47.5 / Dart 3.13.0，`flutter build macos --release`）：
//!
//! | 语料 | 类/mixin/enum | 字符串字面量 | 源文件→库文件 | analyze |
//! |---|---|---|---|---|
//! | material_3_demo | 85/86 = 98.8% | 293/303 = 96.7% | 18/18 | 0 error |
//! | animations | 35/35 = 100% | 111/114 = 97.4% | 21/23 | 0 error |
//!
//! 下限取 0.90/0.90，比实测留约 7 个百分点余量：够松以免误伤正常的 tree-shake 差异，
//! 够紧以便「类名恢复链路断了」或「池字面量不再内联」立刻失败。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// 门禁跳过点统一走这里：默认打印并跳过，但 `DAE_REQUIRE_GATES=1` 时**直接失败**。
/// 理由见 `tests/ground_truth.rs`：`cargo test` 吞掉 println，「全绿但什么都没量」比红更坏。
fn skip_or_fail(msg: &str) {
    if std::env::var_os("DAE_REQUIRE_GATES").is_some() {
        panic!("DAE_REQUIRE_GATES=1，但门禁跳过了：{msg}");
    }
    println!("{msg}");
}

const CLASS_FLOOR: f64 = 0.90;
const LITERAL_FLOOR: f64 = 0.90;

/// (标签, 相对 DAE_DEMO_ROOT 的项目目录)
const DEMOS: &[(&str, &str)] = &[("material_3_demo", "material_3_demo"), ("animations", "animations")];

fn demo_root() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("DAE_DEMO_ROOT") {
        let pb = PathBuf::from(p);
        return pb.is_dir().then_some(pb);
    }
    let sib = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .parent()?
        .join("github")
        .join("flutter-samples");
    if sib.is_dir() {
        return Some(sib);
    }
    // 退一步：仓库同级的 flutter-samples
    let alt = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .join("flutter-samples");
    alt.is_dir().then_some(alt)
}

/// 产物路径：`<proj>/build/macos/Build/Products/Release/<proj>.app/.../App`。
/// 也接受 Linux/Windows 的常见布局，找不到就返回 None（视为未构建）。
fn artifact(proj: &Path, name: &str) -> Option<PathBuf> {
    let cands = [
        proj.join(format!(
            "build/macos/Build/Products/Release/{name}.app/Contents/Frameworks/App.framework/Versions/A/App"
        )),
        proj.join(format!(
            "build/macos/Build/Products/Release/{name}.app/Contents/Frameworks/App.framework/App"
        )),
        proj.join(format!("build/linux/x64/release/bundle/{name}")),
        proj.join("build/windows/x64/runner/Release/data/app.so"),
    ];
    cands.into_iter().find(|p| p.is_file())
}

/// 不用 regex 依赖：逐行扫 Dart 源码里的类/mixin/enum 声明与单引号字面量。
/// 只取够判定的东西——这是门禁不是解析器，宁可漏也不误判（漏了只会让命中率偏低而失败，
/// 不会假通过）。
fn scan_source(lib: &Path) -> (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>) {
    let mut classes = BTreeSet::new();
    let mut lits = BTreeSet::new();
    let mut files = BTreeSet::new();
    let mut stack: Vec<PathBuf> = vec![lib.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.filter_map(|e| e.ok()) {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if p.extension().map(|x| x != "dart").unwrap_or(true) {
                continue;
            }
            if let Ok(rel) = p.strip_prefix(lib) {
                files.insert(
                    rel.to_string_lossy()
                        .trim_end_matches(".dart")
                        .replace('/', "_"),
                );
            }
            let Ok(t) = std::fs::read_to_string(&p) else { continue };
            for raw in t.lines() {
                let l = raw.trim_start();
                if l.starts_with("//") || l.starts_with("*") {
                    continue;
                }
                // class / mixin / enum 声明（允许 abstract/final/sealed/base/interface 前缀）
                let body = ["abstract ", "final ", "sealed ", "base ", "interface "]
                    .iter()
                    .fold(l, |acc, p| acc.strip_prefix(p).unwrap_or(acc));
                for kw in ["class ", "mixin ", "enum "] {
                    if let Some(rest) = body.strip_prefix(kw) {
                        let nm: String = rest
                            .chars()
                            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
                            .collect();
                        // 只要大写开头的公开类型名：私有名与局部名的恢复率本就不同，
                        // 混在一起会让下限失去意义
                        if nm.starts_with(|c: char| c.is_ascii_uppercase()) {
                            classes.insert(nm);
                        }
                    }
                }
                // 单引号字面量（4..40 字符、含字母、不是 import/路径/URL）
                let chars: Vec<char> = l.chars().collect();
                let mut i = 0;
                while i < chars.len() {
                    if chars[i] == '\'' {
                        let mut j = i + 1;
                        let mut buf = String::new();
                        let mut esc = false;
                        while j < chars.len() {
                            let c = chars[j];
                            if esc {
                                buf.push(c);
                                esc = false;
                            } else if c == '\\' {
                                esc = true;
                            } else if c == '\'' || c == '\n' {
                                break;
                            } else {
                                buf.push(c);
                            }
                            j += 1;
                        }
                        let n = buf.chars().count();
                        if j < chars.len()
                            && chars[j] == '\''
                            && (4..=40).contains(&n)
                            && buf.chars().filter(|c| c.is_ascii_alphabetic()).count() >= 3
                            && !buf.starts_with("package:")
                            && !buf.starts_with("dart:")
                            && !buf.starts_with('/')
                            && !buf.starts_with("http")
                        {
                            lits.insert(buf);
                        }
                        i = j + 1;
                    } else {
                        i += 1;
                    }
                }
            }
        }
    }
    (classes, lits, files)
}

struct Report {
    label: String,
    cls_total: usize,
    cls_hit: usize,
    lit_total: usize,
    lit_hit: usize,
    file_total: usize,
    file_hit: usize,
    missed: Vec<String>,
}

/// 跑一遍：普通导出（不反编译，秒级）→ 对源码判类名/字面量/库文件映射。
fn check_demo(bin: &str, root: &Path, name: &str, proj_dir: &str, work: &Path) -> Option<Report> {
    let proj = root.join(proj_dir);
    let lib = proj.join("lib");
    if !lib.is_dir() {
        println!("  {name}: 没有 lib/，跳过");
        return None;
    }
    let Some(art) = artifact(&proj, name) else {
        println!("  {name}: 未找到构建产物（先跑 flutter build macos --release），跳过");
        return None;
    };
    let (classes, lits, files) = scan_source(&lib);
    if classes.is_empty() {
        println!("  {name}: 源码里没扫出类型声明，跳过（扫描器可能失配）");
        return None;
    }
    let out = work.join(name);
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).ok()?;
    let st = Command::new(bin)
        .args([art.to_str()?, out.to_str()?])
        .output()
        .expect("启动 dae");
    assert!(
        st.status.success(),
        "{name}: dae 导出失败：{}",
        String::from_utf8_lossy(&st.stderr)
    );
    let stderr = String::from_utf8_lossy(&st.stderr).to_string();
    let warns = stderr.lines().filter(|l| l.starts_with("warning")).count();
    assert_eq!(warns, 0, "{name}: 导出有 {warns} 条警告：{stderr}");

    // classes.txt 的形状是 `ref \t cid \t library \t 类名`——类名在第 4 列
    let mut have = BTreeSet::new();
    if let Ok(t) = std::fs::read_to_string(out.join("text/classes.txt")) {
        for l in t.lines() {
            let p: Vec<&str> = l.split('\t').collect();
            if p.len() >= 4 {
                have.insert(p[3].to_string());
            }
        }
    }
    assert!(
        !have.is_empty(),
        "{name}: classes.txt 是空的——类名恢复链路断了，或产物形状变了"
    );
    let cls_hit = classes.iter().filter(|c| have.contains(*c)).count();
    let missed: Vec<String> = classes
        .iter()
        .filter(|c| !have.contains(*c))
        .take(8)
        .cloned()
        .collect();

    let blob = std::fs::read_to_string(out.join("text/strings.txt")).unwrap_or_default();
    let lit_hit = lits.iter().filter(|s| blob.contains(s.as_str())).count();

    // 库映射：源码 `lib/a/b.dart` 应能在 `text/libs.txt` 的库 URL 里找到对应的
    // `package:<pkg>/a/b.dart`。用 libs.txt 而不是 dart/ 下的文件名——`dart/` 只有
    // 加 `--decompile` 才产出，而这个测试刻意跑普通导出（秒级）以便进常规门禁。
    let mut libs: Vec<String> = Vec::new();
    if let Ok(t) = std::fs::read_to_string(out.join("text/libs.txt")) {
        for l in t.lines() {
            let p: Vec<&str> = l.split('\t').collect();
            if p.len() < 2 {
                continue;
            }
            // `package:foo/a/b.dart` → `a_b`；`dart:core` 这类直接跳过
            let Some(rest) = p[1].strip_prefix("package:") else { continue };
            let norm = rest
                .trim_end_matches(".dart")
                .replace('/', "_");
            libs.push(norm);
        }
    }
    assert!(
        !libs.is_empty(),
        "{name}: libs.txt 里一个 package: 库都没有——库名恢复断了"
    );
    let file_hit = files
        .iter()
        .filter(|f| libs.iter().any(|l| l == *f || l.ends_with(&format!("_{f}"))))
        .count();

    Some(Report {
        label: name.to_string(),
        cls_total: classes.len(),
        cls_hit,
        lit_total: lits.len(),
        lit_hit,
        file_total: files.len(),
        file_hit,
        missed,
    })
}

/// 快速档：只做普通导出 + 源码对拍（每个语料秒级），因此可以进常规门禁。
#[test]
fn app_source_truth() {
    let Some(root) = demo_root() else {
        skip_or_fail("app_source_truth: 没有 flutter-samples 检出（设 DAE_DEMO_ROOT 指向它）——跳过");
        return;
    };
    let bin = env!("CARGO_BIN_EXE_dae");
    let work = std::env::temp_dir().join("dae_app_truth");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();

    let mut ran = 0usize;
    for (label, dir) in DEMOS {
        let Some(r) = check_demo(bin, &root, label, dir, &work) else { continue };
        ran += 1;
        let cr = r.cls_hit as f64 / r.cls_total.max(1) as f64;
        let lr = r.lit_hit as f64 / r.lit_total.max(1) as f64;
        println!(
            "{:<18} 类 {:>3}/{:<3} = {:>5.1}%   字面量 {:>3}/{:<3} = {:>5.1}%   源文件→库 {:>2}/{:<2}",
            r.label, r.cls_hit, r.cls_total, cr * 100.0, r.lit_hit, r.lit_total, lr * 100.0,
            r.file_hit, r.file_total
        );
        if !r.missed.is_empty() {
            println!("    未命中的类型（多为 tree-shake 掉或只在未编译分支里）: {:?}", r.missed);
        }
        assert!(
            cr >= CLASS_FLOOR,
            "{}: 源码里的公开类型只恢复到 {:.1}%（下限 {:.0}%），未命中 {:?}",
            r.label,
            cr * 100.0,
            CLASS_FLOOR * 100.0,
            r.missed
        );
        assert!(
            lr >= LITERAL_FLOOR,
            "{}: 源码字符串字面量只出现 {:.1}%（下限 {:.0}%）——池常量内联可能断了",
            r.label,
            lr * 100.0,
            LITERAL_FLOOR * 100.0
        );
        assert!(
            r.file_hit > 0,
            "{}: 一个源码文件都没映射到库文件——库名恢复断了",
            r.label
        );
    }
    if ran == 0 {
        skip_or_fail("app_source_truth: flutter-samples 里一个已构建的 demo 都没有——跳过");
    }
}

/// 慢档：反编译 + `dart analyze`。十万条语句量级要几分钟，所以默认 `#[ignore]`，
/// 发版前跑：`cargo test --release --test app_truth -- --ignored --nocapture`
#[test]
#[ignore]
fn app_output_compiles() {
    let Some(root) = demo_root() else {
        println!("app_output_compiles: 没有 flutter-samples 检出——跳过");
        return;
    };
    if Command::new("dart").arg("--version").output().is_err() {
        println!("app_output_compiles: 没有 dart——跳过");
        return;
    }
    let bin = env!("CARGO_BIN_EXE_dae");
    let work = std::env::temp_dir().join("dae_app_truth_compile");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();

    let mut ran = 0usize;
    for (label, dir) in DEMOS {
        let proj = root.join(dir);
        let Some(art) = artifact(&proj, label) else {
            println!("  {label}: 未构建，跳过");
            continue;
        };
        ran += 1;
        let out = work.join(label);
        std::fs::create_dir_all(&out).unwrap();
        let st = Command::new(bin)
            .args([art.to_str().unwrap(), out.to_str().unwrap(), "--decompile"])
            .output()
            .expect("启动 dae");
        assert!(st.status.success(), "{label}: 反编译失败");
        let summary = String::from_utf8_lossy(&st.stdout).to_string();
        let line = summary.lines().find(|l| l.contains("function pseudocode blocks"));
        println!("  {label}: {}", line.unwrap_or("(无摘要行)").trim());

        let an = Command::new("dart")
            .args(["analyze", "."])
            .current_dir(out.join("dart"))
            .output()
            .expect("启动 dart analyze");
        let text = String::from_utf8_lossy(&an.stdout);
        let rc = an.status.code().unwrap_or(-1);
        let errs: Vec<&str> = text.lines().filter(|l| l.trim_start().starts_with("error -")).collect();
        // 与 source_truth/dart_valid 同一套自证：退出码与解析结果必须互相印证，
        // 且 dart 自己的总结行必须出现，否则「0 错误」毫无意义
        let summarized = text.contains("No issues found")
            || text.contains("issues found")
            || text.contains("issue found");
        let agrees = match rc {
            3 => !errs.is_empty(),
            0..=2 => errs.is_empty(),
            _ => false,
        };
        assert!(
            summarized && agrees,
            "{label}: dart analyze 结果无法自证（rc={rc}，解析到 {} 条 error，总结行={summarized}）",
            errs.len()
        );
        println!("  {label}: dart analyze error={} rc={rc}", errs.len());
        assert!(
            errs.is_empty(),
            "{label}: 产物有 {} 个 dart analyze 错误，例如 {:?}",
            errs.len(),
            errs.first()
        );
    }
    assert!(ran > 0, "一个已构建的 demo 都没有，门禁形同虚设");
}
