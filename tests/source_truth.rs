//! 源码真值门禁：自己编一个程序，再拿 dae 逆向它，对着**源码**判结果。
//!
//! 语料是 `tests/fixtures/truth.dart`（覆盖类/继承/泛型/闭包/枚举/集合/循环/switch/
//! try-catch/async/字符串插值/递归）。用本机 `dart compile exe` 现编现测，因此断言不依赖
//! 任何预置二进制；`dart` 不在 PATH 时整条测试跳过（与其它门禁一致）。
//!
//! 判据都是**版本无关**的形态，不写死内联结果（AOT 会把只用一次的方法内联掉，那属于
//! 编译器的事实，不是 dae 的漏）：
//! 1. **覆盖**：快照里归属真值库的每个函数都渲染了出来；
//! 2. **字面量**：`main` 一定会走到的字符串常量出现在伪代码里；
//! 3. **语义形态**：`Account.withdraw`（若未被内联）必须带着 `-1` 分支与比较；
//! 4. **可编译**：`dart analyze` 零错误（警告只打印不断言——那是机器寄存器视角的噪声，
//!    见 docs/DECOMPILER.md「已知短板」）；
//! 5. **解析不漂**：自家源码产物一旦出现 `!!! drift` 就直接失败（这是 profile/布局回归
//!    的第一信号，此前正是靠它才发现移动端压缩指针产物解析不了）。
//!
//! 移动端链路（压缩指针 arm64）是**可选**的：`DAE_TRUTH_ANDROID=1` 时用
//! `flutter assemble -dTargetPlatform=android-arm64 -dBuildMode=release` 现编一份
//! `app.so` 再跑同一套判据。默认跳过——它要 flutter 工具链与 android 引擎缓存，
//! 而且刻意绕开 Gradle（首跑会长时间卡在依赖下载）。

use dae::analyzer::Analyzer;
use std::path::Path;

/// 门禁跳过点统一走这里：默认打印并跳过，但 `DAE_REQUIRE_GATES=1` 时**直接失败**。
/// 显式 opt-in（未设 `DAE_TRUTH_ANDROID`）不属于「缺依赖」，不走这里。
fn skip_or_fail(msg: &str) {
    if std::env::var_os("DAE_REQUIRE_GATES").is_some() {
        panic!("DAE_REQUIRE_GATES=1，但门禁跳过了：{msg}");
    }
    println!("{msg}");
}

fn which(cmd: &str) -> Option<String> {
    std::process::Command::new("which")
        .arg(cmd)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// `dart analyze <dir>` → (error 条数, 诊断码 → 条数)。
///
/// **只有「本机没有 dart」才返回 None**（那是合法跳过）。analyze 真跑了却看不懂输出时
/// **直接 panic**，绝不静默返回 0：实测 `dart analyze /不存在的路径` 返回 rc=64 + usage
/// 文本，里面一条 `error - ` 都没有，旧实现会解析出 `errors=0` 然后断言通过——
/// 门禁在根本没分析任何文件的情况下绿灯，正是本项目反复踩过的「假门禁」形态。
fn analyze(dir: &Path) -> Option<(usize, Vec<(String, usize)>)> {
    let dart = which("dart")?;
    let out = std::process::Command::new(&dart)
        .args(["analyze", &dir.display().to_string()])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let rc = out.status.code().unwrap_or(-1);
    let mut errors = 0usize;
    let mut codes: std::collections::BTreeMap<String, usize> = Default::default();
    for line in text.lines() {
        let Some((level, rest)) = line
            .trim_start()
            .strip_prefix("error - ")
            .map(|r| ("error", r))
            .or_else(|| line.trim_start().strip_prefix("warning - ").map(|r| ("warning", r)))
            .or_else(|| line.trim_start().strip_prefix("info - ").map(|r| ("info", r)))
        else {
            continue;
        };
        if level == "error" {
            errors += 1;
        }
        if let Some(code) = rest.rsplit(" - ").next() {
            *codes.entry(code.trim().to_string()).or_insert(0) += 1;
        }
    }

    // 自证 1：必须有 dart 自己的总结行，否则说明输出格式变了（解析到的 0 毫无意义）
    let summarized = text.contains("No issues found")
        || text.contains("issues found")
        || text.contains("issue found");
    // 自证 2：退出码与解析结果必须互相印证。实测语义：
    // 0=无问题、2=仅 warning/info、3=有 error、64=usage 错误（路径不存在等）
    let rc_agrees = match rc {
        3 => errors > 0,
        0 | 1 | 2 => errors == 0,
        _ => false,
    };
    if !summarized || !rc_agrees {
        panic!(
            "dart analyze 结果无法自证（rc={rc}，解析到 {errors} 个 error，总结行出现={summarized}）。\n\
             要么输出格式变了，要么目标目录不存在/为空——两种情况都不能当作「0 错误」放过。\n\
             目标目录：{}\nstdout 前 400 字：{}",
            dir.display(),
            text.chars().take(400).collect::<String>()
        );
    }
    Some((errors, codes.into_iter().collect()))
}

/// 从渲染全文里取某个函数体（`dynamic <name>() {` 到行首 `}`）
fn fn_body(all: &str, name: &str) -> Option<String> {
    let start = all.find(&format!("dynamic {name}() {{"))?;
    let rest = &all[start..];
    let end = rest.find("\n}\n")?;
    Some(rest[..end].to_string())
}

/// 跑完整套判据：解析 → 反编译 → 落盘 → 对照源码断言。
fn check(bin: &Path, out: &Path, label: &str, plat_name: &str) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let plat_src = std::fs::read_to_string(root.join("profiles/platform").join(plat_name))
        .expect("平台 profile");
    let plat = dae::profile::parse_platform(&plat_src).expect("解析平台 profile");
    let s = dae::locale::messages(dae::locale::Lang::En);
    let data: &'static [u8] = Box::leak(std::fs::read(bin).unwrap().into_boxed_slice());
    let (offs, _) = dae::platform::locate_snapshots(data, &plat).expect("定位快照");
    let sdk = dae::profile::detect::detect_or_default(data, offs, &s);
    let a = Analyzer::new_located(data, &sdk, &plat, offs, false).expect("解析快照");
    assert!(
        !a.warnings.iter().any(|w| w.starts_with("!!! drift")),
        "{label}: 自家源码产物解析漂移（profile/布局回归）：{:?}",
        a.warnings
    );

    let libs = a.build_functions(true);
    let (files, stats) = dae::decompiler::render(&a, &libs).expect("反编译渲染");
    std::fs::create_dir_all(out.join("dart")).expect("建 dart 目录");
    let mut all = String::new();
    for (name, body) in &files {
        std::fs::write(out.join("dart").join(name), body).expect("写产物");
        all.push_str(body);
    }
    println!("{label}: 反编译 {} 个函数 / {} 个库", stats.funcs, libs.len());
    assert!(stats.funcs > 0, "{label}: 一个函数都没反编译出来");

    // 1) 覆盖：快照里归属真值库的函数都要渲染出来
    let mut declared = 0usize;
    let mut missing: Vec<String> = Vec::new();
    for (lib, cls_map) in &libs {
        if !lib.contains("truth") {
            continue; // 真值库在桌面叫 truth$truth、在 Flutter 里叫 truthapp$main
        }
        for (cls, funcs) in cls_map {
            for f in funcs {
                declared += 1;
                let rendered = format!(
                    "{}{}",
                    if cls.is_empty() { String::new() } else { format!("{cls}_") },
                    f.mangled
                );
                if !all.contains(&rendered) {
                    missing.push(rendered);
                }
            }
        }
    }
    assert!(declared > 0, "{label}: 快照里没找到真值库的函数（库名匹配规则要跟着 Dart 版本改）");
    assert!(
        missing.is_empty(),
        "{label}: {} 个已声明函数没渲染出来：{:?}",
        missing.len(),
        &missing[..missing.len().min(6)]
    );

    // 2) 字面量：classify() 的四个分支常量（main 一定会调用到）
    for lit in ["zero", "one", "positive", "negative"] {
        assert!(all.contains(lit), "{label}: 源码字面量 '{lit}' 没出现在产物里");
    }

    // 3) 语义形态（被内联就跳过——那是编译器的事实）
    match fn_body(&all, "Account_withdraw") {
        Some(body) => {
            assert!(body.contains("-1"), "{label}: withdraw 的 -1 分支丢了");
            assert!(
                body.contains('>') || body.contains('<') || body.contains("=="),
                "{label}: withdraw 的比较条件没了：{body}"
            );
        }
        None => println!("{label}: Account_withdraw 被编译器内联，跳过形态断言"),
    }
    if let Some(body) = fn_body(&all, "Account_describe") {
        assert!(
            body.contains(": ") || body.contains("owner"),
            "{label}: describe 的插值串没恢复：{body}"
        );
    }

    // 4) 可编译
    match analyze(&out.join("dart")) {
        Some((errors, codes)) => {
            println!("{label}: dart analyze error={errors} 诊断={codes:?}");
            assert_eq!(errors, 0, "{label}: 产物有 dart analyze 错误");
        }
        None => println!("{label}: 本机没有 dart，跳过可编译性检查（其余判据已执行）"),
    }
}

#[test]
fn source_truth_desktop() {
    let Some(dart) = which("dart") else {
        skip_or_fail("source_truth_desktop: 没有 dart，跳过");
        return;
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let work = std::env::temp_dir().join("dae_source_truth_desktop");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    let bin = work.join("truth");
    let st = std::process::Command::new(&dart)
        .args([
            "compile",
            "exe",
            root.join("tests/fixtures/truth.dart").to_str().unwrap(),
            "-o",
            bin.to_str().unwrap(),
        ])
        .output()
        .expect("调用 dart compile");
    assert!(
        st.status.success(),
        "dart compile 失败：{}",
        String::from_utf8_lossy(&st.stderr)
    );
    // `dart compile exe` 不做交叉编译，产物容器与架构就等于宿主，
    // 因此按 host OS/ARCH 选 profile。曾按魔数二分支（ELF→x64，否则→macho-arm64），
    // 那在 linux-arm64 上会选成 elf-x64、在 windows 上会选成 macho-arm64，门禁自身就不可移植。
    let plat = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "elf-x64.json",
        ("linux", "aarch64") => "elf-arm64.json",
        ("macos", "x86_64") => "macho-x64.json",
        ("macos", "aarch64") => "macho-arm64.json",
        ("windows", "x86_64") => "pe-x64.json",
        ("windows", "aarch64") => "pe-arm64.json",
        (os, arch) => {
            println!("source_truth_desktop: 宿主 {os}/{arch} 没有对应 platform profile，跳过");
            return;
        }
    };
    check(&bin, &work.join("out"), "desktop", plat);
}

/// 移动端（压缩指针 arm64）：`DAE_TRUTH_ANDROID=1` 才跑。
#[test]
fn source_truth_android_optin() {
    if std::env::var("DAE_TRUTH_ANDROID").is_err() {
        println!("source_truth_android: 未设 DAE_TRUTH_ANDROID，跳过");
        return;
    }
    let Some(flutter) = which("flutter") else {
        skip_or_fail("source_truth_android: 没有 flutter，跳过");
        return;
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let work = std::env::temp_dir().join("dae_source_truth_android");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();

    let st = std::process::Command::new(&flutter)
        .args([
            "create",
            "--platforms=android",
            "--project-name",
            "truthapp",
            work.join("app").to_str().unwrap(),
        ])
        .output()
        .expect("flutter create");
    assert!(st.status.success(), "flutter create 失败：{}", String::from_utf8_lossy(&st.stderr));

    // fixture 直接当 lib/main.dart，末尾换成一个最小 runApp 壳（import 必须在声明之前）
    let src = std::fs::read_to_string(root.join("tests/fixtures/truth.dart")).unwrap();
    let head = &src[..src.find("void main() {").expect("fixture 应有 main")];
    std::fs::write(
        work.join("app/lib/main.dart"),
        format!(
            "import 'package:flutter/material.dart' show runApp, MaterialApp, Scaffold, Center, Text;\n\n{head}\nvoid main() {{\n  runApp(const MaterialApp(home: Scaffold(body: Center(child: Text('truth')))));\n}}\n"
        ),
    )
    .unwrap();

    // 绕开 Gradle，直跑 Flutter 的 Android AOT 目标 → arm64-v8a/app.so（压缩指针）
    let st = std::process::Command::new(&flutter)
        .current_dir(work.join("app"))
        .args([
            "assemble",
            "-dTargetPlatform=android-arm64",
            "-dBuildMode=release",
            "--output",
            work.join("aot").to_str().unwrap(),
            "android_aot_bundle_release_android-arm64",
        ])
        .output()
        .expect("flutter assemble");
    assert!(
        st.status.success(),
        "flutter assemble 失败：{}",
        String::from_utf8_lossy(&st.stderr)
    );
    let so = work.join("aot/arm64-v8a/app.so");
    assert!(so.exists(), "没产出 app.so");
    check(&so, &work.join("out"), "android", "elf-arm64.json");
}

/// **门禁自检**：目录不存在时必须炸，不能静默报 0 错误。
/// 这条测的是门禁本身——`dart analyze /不存在的路径` 返回 rc=64 + usage 文本，
/// 里面一条 `error - ` 都没有，旧实现解析出 `errors=0` 然后断言通过，
/// 等于在根本没分析任何文件的情况下给产物盖了「可编译」的章。
#[test]
fn analyze_rejects_directory_it_never_analyzed() {
    if which("dart").is_none() {
        skip_or_fail("analyze_rejects_directory_it_never_analyzed: 没有 dart，跳过");
        return;
    }
    let bogus = Path::new("/tmp/dae_gate_selfcheck_definitely_not_here");
    let r = std::panic::catch_unwind(|| analyze(bogus));
    assert!(
        r.is_err(),
        "门禁自证失效：analyze() 对一个它根本没分析过的目录没有报错，\
         假通过洞又回来了（见 docs/DECOMPILER.md 的「假门禁」教训）"
    );
}
