//! 渐进式命令行：先查列表，再按需反编译某个类或某个库。
//!
//! 设计对齐同类工具的命令行范式（`/Users/e/Documents/project/ddc` 的 ddc-cli）：
//! 全量反编译是一条命令，**查询/定点反编译是一组子命令**，查询结果默认走 stdout
//! （可直接管道），`-o FILE` 才落盘；输出目录形态与全量导出一致（`dart/<库>.dart`）。
//!
//! 与 ddc 的差别（domain 决定，不是简化）：dae 的快照解析本身只有几十毫秒，慢的是
//! **落盘全量产物**。实测（真实 Flutter 应用 10 245 个函数）：全量导出 `--decompile`
//! 1.9 秒，而 `getclass` 0.03 秒、`info`/`libs` 0.03 秒、最贵的 `callers`（要扫全量调用点）
//! 0.18 秒。所以这里的价值不在省解析，而在「不写上千个文件、只取你要的那一份」。
//!
//! 命名口径（用户要能猜中）：
//! * 库：`functions.txt` 的 `lib` 列（`testing_app$screens$home`）、`libs.txt` 的 URL
//!   （`package:testing_app/screens/home.dart`）、产物文件名（`testing_app_screens_home`）
//!   三种写法都认，见 `selection::norm_lib`；库名支持**前缀**匹配（`--lib testing_app`）。
//! * 类：精确匹配（大小写不敏感兜底），`--fuzzy` 才子串。
//! * 函数：`Class.method`、`Class.method`、裸 `method` 都认。

#[cfg(feature = "asm")]
use crate::analyzer::LibGroups;
use crate::analyzer::Analyzer;
use crate::locale::{Lang, Messages};
use crate::profile::{parse_platform, parse_sdk, PlatformProfile, SdkProfile};
use crate::selection::{counts, filter_libs, name_hit, norm_lib, Selection};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

pub const SUBCOMMANDS: &[&str] = &[
    "info",
    "libs",
    "classes",
    "functions",
    "strings",
    "largest",
    "callers",
    "disasm",
    "getclass",
    "getmethod",
    "getlib",
    "help",
    "version",
];

pub fn is_subcommand(a: &str) -> bool {
    SUBCOMMANDS.contains(&a)
}

/// 子命令双语短句：`(中文, English)`
fn tr(lang: Lang, zh: &str, en: &str) -> String {
    match lang {
        Lang::Zh => zh.to_string(),
        Lang::En => en.to_string(),
    }
}

// ---------------------------------------------------------------- 参数

#[derive(Default)]
struct Opts {
    bin: Option<String>,
    sdk: Option<PathBuf>,
    platform: Option<PathBuf>,
    out: Option<String>,
    n: Option<usize>,
    find: Option<String>,
    libs: Vec<String>,
    classes: Vec<String>,
    funcs: Vec<String>,
    fuzzy: bool,
    /// 位置参数（除 <binary> 与选项外的其余）
    rest: Vec<String>,
}

/// 统一解析：`<binary>` 恒为第一个位置参数，其余位置参数进 `rest`。
fn parse_opts(args: &[String], cmd: &str, lang: Lang) -> Result<Opts, String> {
    let mut o = Opts::default();
    let need = |i: usize, what: &str| -> Result<String, String> {
        args.get(i + 1)
            .cloned()
            .ok_or_else(|| tr(lang, &format!("{cmd}：{what} 缺少取值"), &format!("{cmd}: {what} needs a value")))
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--sdk-profile" => {
                o.sdk = Some(PathBuf::from(need(i, "--sdk-profile")?));
                i += 2;
            }
            "--platform-profile" => {
                o.platform = Some(PathBuf::from(need(i, "--platform-profile")?));
                i += 2;
            }
            "-o" | "--output" => {
                o.out = Some(need(i, "-o")?);
                i += 2;
            }
            "-n" | "--limit" => {
                o.n = Some(
                    need(i, "-n")?
                        .parse()
                        .map_err(|_| tr(lang, "-n 需要一个数字", "-n needs a number"))?,
                );
                i += 2;
            }
            "-f" | "--find" => {
                o.find = Some(need(i, "-f")?);
                i += 2;
            }
            "--lib" => {
                o.libs.push(need(i, "--lib")?);
                i += 2;
            }
            "--class" => {
                o.classes.push(need(i, "--class")?);
                i += 2;
            }
            "--func" => {
                o.funcs.push(need(i, "--func")?);
                i += 2;
            }
            "--fuzzy" => {
                o.fuzzy = true;
                i += 1;
            }
            "-h" | "--help" => {
                println!("{}", help_for(cmd, lang));
                std::process::exit(0);
            }
            a if a.starts_with('-') && a.len() > 1 && a != "-" => {
                return Err(tr(lang, &format!("{cmd}：未知选项 {a}"), &format!("{cmd}: unknown option {a}")));
            }
            a => {
                if o.bin.is_none() {
                    o.bin = Some(a.to_string());
                } else {
                    o.rest.push(a.to_string());
                }
                i += 1;
            }
        }
    }
    Ok(o)
}

impl Opts {
    fn selection(&self) -> Selection {
        Selection {
            libs: self.libs.clone(),
            classes: self.classes.clone(),
            funcs: self.funcs.clone(),
            fuzzy: self.fuzzy,
        }
    }
    fn bin(&self, cmd: &str, lang: Lang) -> Result<&str, String> {
        self.bin
            .as_deref()
            .ok_or_else(|| tr(lang, &format!("{cmd}：需要一个 Dart AOT 产物路径"), &format!("{cmd}: needs a Dart AOT binary path")))
    }
}

// ---------------------------------------------------------------- 载入

/// 解析平台 profile（显式覆盖，或按容器 + 架构自动选择）。
/// 与全量导出共用同一份逻辑（原来内联在 main.rs 的 run() 里）。
pub fn resolve_platform(
    data: &[u8],
    override_path: Option<&Path>,
    s: &Messages,
) -> Result<PlatformProfile, String> {
    if let Some(p) = override_path {
        let c = std::fs::read_to_string(p).map_err(|e| format!("{}{e}", s.err_read_platform))?;
        return parse_platform(&c);
    }
    let kind = crate::platform::detect_container(data).ok_or_else(|| {
        if data.len() >= 4 && data[..4] == [0xdc, 0xdc, 0xf6, 0xf6] {
            s.err_bare_jit.to_string()
        } else {
            s.err_container.to_string()
        }
    })?;
    let arch = match kind {
        "macho" => {
            let slice = crate::platform::macho::fat_slice_offset(data);
            if slice + 8 > data.len() {
                None
            } else {
                match u32::from_le_bytes(data[slice + 4..slice + 8].try_into().unwrap()) {
                    0x0100_000C => Some("arm64"),
                    0x0100_0007 => Some("x64"),
                    0x0000_000C => Some("arm"),
                    _ => None,
                }
            }
        }
        "elf" => match u16::from_le_bytes([data[18], data[19]]) {
            62 => Some("x64"),
            183 => Some("arm64"),
            40 => Some("arm"),
            243 => Some("riscv"),
            _ => None,
        },
        "pe" => {
            let lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
            if lfanew + 6 > data.len() {
                None
            } else {
                match u16::from_le_bytes(data[lfanew + 4..lfanew + 6].try_into().unwrap()) {
                    0x8664 => Some("x64"),
                    0xAA64 => Some("arm64"),
                    0x014C => Some("x86"),
                    0x01C0 => Some("arm"),
                    _ => None,
                }
            }
        }
        _ => None,
    };
    let embedded: &str = match (kind, arch) {
        ("macho", Some("arm64")) => include_str!("../profiles/platform/macho-arm64.json"),
        ("elf", Some("arm64")) => include_str!("../profiles/platform/elf-arm64.json"),
        ("elf", Some("x64")) => include_str!("../profiles/platform/elf-x64.json"),
        ("macho", Some("x64")) => include_str!("../profiles/platform/macho-x64.json"),
        ("pe", Some("x64")) => include_str!("../profiles/platform/pe-x64.json"),
        ("pe", Some("arm64")) => include_str!("../profiles/platform/pe-arm64.json"),
        _ => {
            return Err(format!(
                "container {kind} arch {arch:?}: {}",
                s.err_platform_missing
            ))
        }
    };
    parse_platform(embedded)
}

/// 找二进制：目录按 macOS Flutter 布局展开（`xxx.app/Contents/Frameworks/App.framework/App`）。
pub fn resolve_binary(path: &str, s: &Messages) -> Result<String, String> {
    let p = Path::new(path);
    if p.is_dir() {
        let candidates = vec![
            p.join("Contents/Frameworks/App.framework/App"),
            p.join("Frameworks/App.framework/App"),
            p.join("App"),
        ];
        for c in &candidates {
            if c.is_file() {
                return Ok(c.to_string_lossy().to_string());
            }
        }
        return Err(format!(
            "{} {path}（{}）",
            s.err_flutter_dir,
            candidates
                .iter()
                .map(|c| c.to_string_lossy())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(path.to_string())
}

/// 读文件 → 定平台 → 定快照 → 认 SDK → 建 Analyzer，把 Analyzer 交给闭包。
///
/// 用闭包而不是返回 Analyzer，是因为 `Analyzer<'a>` 同时借用 data / platform /
/// sdk 三份数据——把它们和 Analyzer 一起返回就是自引用结构。闭包让这三份数据留在
/// 本函数的栈帧上，借用关系自然成立（也避免为此引入 ouroboros 之类的依赖）。
fn with_analyzer<T>(
    bin: &str,
    sdk: Option<&Path>,
    plat: Option<&Path>,
    s: &Messages,
    quiet: bool,
    f: impl FnOnce(&Analyzer, &PlatformProfile, &SdkProfile) -> Result<T, String>,
) -> Result<T, String> {
    let bin_path = resolve_binary(bin, s)?;
    let data = std::fs::read(&bin_path)
        .map_err(|e| format!("{} {bin_path}: {e}", s.err_read_binary))?;
    let platform = resolve_platform(&data, plat, s)?;
    let (offs, used_fallback) = crate::platform::locate_snapshots(&data, &platform)?;
    // SDK profile：覆盖时是本地拥有的，自动识别时是内嵌的 'static——两种都要能借给 Analyzer
    let sdk_owned: Option<SdkProfile>;
    let sdk: &SdkProfile = match sdk {
        Some(p) => {
            let c = std::fs::read_to_string(p).map_err(|e| format!("读 --sdk-profile: {e}"))?;
            sdk_owned = Some(parse_sdk(&c)?);
            sdk_owned.as_ref().unwrap()
        }
        None => crate::profile::detect::detect_or_default(&data, offs, s),
    };
    let a = Analyzer::new_located(&data, &sdk, &platform, offs, used_fallback)?;
    if !quiet {
        // 诊断一律走 stderr：stdout 要留给数据（可管道）
        // SDK 行由 detect 自己打（同样是 stderr），这里只报目标与规模无关的定位信息
        eprintln!("{}: {} ({} {})", s.target_label, bin_path, platform.container.kind, platform.arch);
        for w in &a.warnings {
            eprintln!("{}: {w}", s.warn_prefix);
        }
    }
    let _ = sdk;
    f(&a, &platform, sdk)
}

// ---------------------------------------------------------------- 输出

/// 把结果写到 `-o` 指定的位置；无 `-o` 或 `-o -` 时走 stdout。
fn emit(o: &Opts, body: &str, lang: Lang, what: &str) -> Result<(), String> {
    match o.out.as_deref() {
        None | Some("-") => {
            print!("{body}");
            Ok(())
        }
        Some(p) => {
            if let Some(parent) = Path::new(p).parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
            std::fs::write(p, body).map_err(|e| format!("{p}: {e}"))?;
            eprintln!(
                "{}",
                tr(
                    lang,
                    &format!("dae：已写出 {p}（{what}）"),
                    &format!("dae: wrote {p} ({what})")
                )
            );
            Ok(())
        }
    }
}

fn limit_of(o: &Opts, dflt: usize) -> usize {
    o.n.unwrap_or(dflt)
}

/// 没命中时给「是不是想找」提示：放宽成子串匹配重新选一遍，最多列 5 个。
#[cfg(feature = "asm")]
fn suggest(libs: &LibGroups, sel: &Selection) -> Vec<String> {
    let mut loose = sel.clone();
    loose.fuzzy = true;
    let f = filter_libs(libs, &loose);
    let mut v: Vec<String> = Vec::new();
    for (lib, cls_map) in &f {
        for (cls, funcs) in cls_map {
            for e in funcs {
                v.push(if cls.is_empty() {
                    format!("{lib}.{}", e.mangled)
                } else {
                    format!("{lib}/{cls}.{}", e.mangled)
                });
                if v.len() >= 5 {
                    return v;
                }
            }
        }
    }
    v
}

#[cfg(feature = "asm")]
fn no_match(cmd: &str, sel: &Selection, libs: &LibGroups, lang: Lang) -> String {
    let what = if !sel.funcs.is_empty() {
        sel.funcs.join(", ")
    } else if !sel.classes.is_empty() {
        sel.classes.join(", ")
    } else {
        sel.libs.join(", ")
    };
    let mut m = tr(
        lang,
        &format!("{cmd}：没有命中「{what}」"),
        &format!("{cmd}: nothing matched \"{what}\""),
    );
    let s = suggest(libs, sel);
    if !s.is_empty() {
        let _ = write!(
            m,
            "\n  {}{}",
            tr(lang, "是不是想找：", "did you mean: "),
            s.join(", ")
        );
    }
    m
}

// ---------------------------------------------------------------- 子命令

pub fn dispatch(args: &[String], lang: Lang, s: &Messages) -> i32 {
    let cmd = args[0].as_str();
    let rest = &args[1..];
    let r = match cmd {
        "help" => {
            println!(
                "{}",
                match rest.first() {
                    Some(c) => help_for(c, lang),
                    None => help(lang),
                }
            );
            Ok(())
        }
        "version" => {
            println!("dae {}", env!("GIT_VERSION"));
            Ok(())
        }
        "info" => cmd_info(rest, lang, s),
        "libs" => cmd_libs(rest, lang, s),
        "classes" => cmd_classes(rest, lang, s),
        "functions" => cmd_functions(rest, lang, s),
        "strings" => cmd_strings(rest, lang, s),
        "largest" => cmd_largest(rest, lang, s),
        "callers" => cmd_callers(rest, lang, s),
        "disasm" => cmd_disasm(rest, lang, s),
        "getclass" | "getmethod" | "getlib" => cmd_get(cmd, rest, lang, s),
        _ => {
            eprintln!(
                "{}",
                tr(lang, &format!("未知子命令 {cmd}"), &format!("unknown subcommand {cmd}"))
            );
            println!("{}", help(lang));
            std::process::exit(2);
        }
    };
    match r {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{}: {e}", s.err_prefix);
            1
        }
    }
}

/// 目标选择：子命令的第二个位置参数（模式串）
#[cfg(feature = "asm")]
fn target_sel(o: &Opts, cmd: &str, lang: Lang, kind: TargetKind) -> Result<Selection, String> {
    let t: String = o
        .rest
        .first()
        .cloned()
        .ok_or_else(|| match kind {
            TargetKind::Class => tr(lang, &format!("{cmd}：需要一个类名（如 HomePage）"), &format!("{cmd}: needs a class name (e.g. HomePage)")),
            TargetKind::Func => tr(lang, &format!("{cmd}：需要一个函数名（如 HomePage.build）"), &format!("{cmd}: needs a function name (e.g. HomePage.build)")),
            TargetKind::Lib => tr(lang, &format!("{cmd}：需要一个库名（如 package:flutter/src/widgets/framework.dart）"), &format!("{cmd}: needs a library name (e.g. package:flutter/src/widgets/framework.dart)")),
            TargetKind::Any => tr(lang, &format!("{cmd}：需要一个名字"), &format!("{cmd}: needs a name")),
        })?;
    let mut sel = o.selection();
    match kind {
        TargetKind::Class => sel.classes.push(t.clone()),
        TargetKind::Func => sel.funcs.push(t.clone()),
        TargetKind::Lib => sel.libs.push(t.clone()),
        TargetKind::Any => sel.funcs.push(t.clone()),
    }
    // 位置参数也可以是「全名」形式 lib/Class.method：同时按函数与类两个维度匹配，
    // 这样 `getclass testing_app/HomePage` 与 `getmethod testing_app/HomePage.build` 都能用
    if t.contains('/') {
        let (head, tail) = t.rsplit_once('/').unwrap();
        sel.libs.push(head.to_string());
        if let Some((c, m)) = tail.split_once('.') {
            sel.classes.push(c.to_string());
            let _ = m;
        } else {
            sel.classes.push(tail.to_string());
        }
    }
    Ok(sel)
}

#[cfg(feature = "asm")]
enum TargetKind {
    Class,
    Func,
    Lib,
    Any,
}

// ---- info ----
fn cmd_info(args: &[String], lang: Lang, s: &Messages) -> Result<(), String> {
    let o = parse_opts(args, "info", lang)?;
    let bin = o.bin("info", lang)?;
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, false, |a, p, sdk| {
        let libs = a.build_functions(true);
        let (nl, nc, nf) = counts(&libs);
        let mut out = String::new();
        let _ = writeln!(out, "{}\t{}", tr(lang, "容器", "container"), p.container.kind);
        let _ = writeln!(out, "{}\t{}", tr(lang, "架构", "arch"), p.arch);
        let _ = writeln!(out, "{}\t{}", tr(lang, "SDK", "sdk"), sdk.abi);
        let _ = writeln!(out, "{}\t{}", tr(lang, "SDK 状态", "sdk status"), sdk.status);
        let _ = writeln!(
            out,
            "{}\t{}",
            tr(lang, "快照", "snapshot"),
            if sdk.format.single_snapshot { "single" } else { "vm+iso" }
        );
        let _ = writeln!(
            out,
            "{}\t{}",
            tr(lang, "指令段基址", "instructions base"),
            format!("{:#x}", a.instr_base)
        );
        let _ = writeln!(
            out,
            "{}\t{}",
            tr(lang, "指令表条目", "instructions table entries"),
            a.pc_offsets.len()
        );
        let _ = writeln!(out, "{}\t{nl}", tr(lang, "库", "libraries"));
        let _ = writeln!(out, "{}\t{nc}", tr(lang, "类", "classes"));
        let _ = writeln!(
            out,
            "{} ({} + {})\t{nf}",
            tr(lang, "函数", "functions"),
            tr(lang, "已反汇编", "disassembled"),
            tr(lang, "无地址", "no address"),
            );
        let _ = writeln!(
            out,
            "{}\t{}",
            tr(lang, "字符串", "strings"),
            a.iso.strings.len() + a.vm.strings.len()
        );
        let _ = writeln!(
            out,
            "{}\t{}",
            tr(lang, "VM/ISO 对象", "VM/ISO objects"),
            format!("{} / {}", a.vm.hdr.get("num_objects"), a.iso.hdr.get("num_objects"))
        );
        let _ = writeln!(
            out,
            "{}\t{}",
            tr(lang, "告警", "warnings"),
            a.warnings.len()
        );
        emit(&o, &out, lang, "info")
    })
}

// ---- libs ----
fn cmd_libs(args: &[String], lang: Lang, s: &Messages) -> Result<(), String> {
    let o = parse_opts(args, "libs", lang)?;
    let bin = o.bin("libs", lang)?;
    let pat = o.rest.first().cloned();
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let libs = a.build_functions(true);
        // 库名 → 类数 / 函数数；同时给出 url（libs.txt 里的原始 URL）便于对上
        let url_of = |target: &str| -> String {
            for (_, rec) in &a.iso.libraries {
                let url = a.sref(rec.url_ref).unwrap_or_default();
                if norm_lib(&url) == norm_lib(target) {
                    return url;
                }
            }
            String::new()
        };
        let mut rows: Vec<(String, usize, usize, String)> = Vec::new();
        for (lib, cls_map) in &libs {
            if let Some(p) = &pat {
                if !(name_hit(p, lib, true) || name_hit(p, &url_of(lib), true)) {
                    continue;
                }
            }
            let nc = cls_map.len();
            let nf: usize = cls_map.iter().map(|(_, f)| f.len()).sum();
            rows.push((lib.clone(), nc, nf, url_of(lib)));
        }
        rows.sort_by(|x, y| y.2.cmp(&x.2).then(x.0.cmp(&y.0)));
        let mut out = String::new();
        for (lib, nc, nf, url) in rows.iter().take(limit_of(&o, usize::MAX)) {
            let _ = writeln!(out, "{lib}\t{nc}\t{nf}\t{url}");
        }
        eprintln!(
            "{}",
            tr(
                lang,
                &format!("dae：命中 {} 个库", rows.len()),
                &format!("dae: {} libraries", rows.len())
            )
        );
        emit(&o, &out, lang, "libs")
    })
}

// ---- classes ----
fn cmd_classes(args: &[String], lang: Lang, s: &Messages) -> Result<(), String> {
    let o = parse_opts(args, "classes", lang)?;
    let bin = o.bin("classes", lang)?;
    let pat = o.rest.first().cloned();
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let libs = filter_libs(&a.build_functions(true), &o.selection());
        // cid 取 iso.classes 的 class_id（与 text/classes.txt 同源），不在表里就写 "-"，
        // 不编一个看起来像 id 的数字
        let mut cid_of: std::collections::BTreeMap<String, i64> = std::collections::BTreeMap::new();
        for rec in a.iso.classes.values() {
            let name = a
                .cname_by_cid
                .get(&rec.class_id)
                .cloned()
                .filter(|s| !s.is_empty())
                .or_else(|| a.sref(rec.name_ref));
            if let Some(n) = name {
                cid_of.entry(n).or_insert(rec.class_id);
            }
        }
        let mut rows: Vec<(String, Option<i64>, String, usize)> = Vec::new();
        for (lib, cls_map) in &libs {
            for (cls, funcs) in cls_map {
                if let Some(p) = &pat {
                    if !name_hit(p, cls, true) {
                        continue;
                    }
                }
                rows.push((lib.clone(), cid_of.get(cls).copied(), cls.clone(), funcs.len()));
            }
        }
        rows.sort_by(|x, y| x.2.cmp(&y.2).then(x.0.cmp(&y.0)));
        let mut out = String::new();
        for (lib, cid, cls, nf) in rows.iter().take(limit_of(&o, usize::MAX)) {
            let cid = match cid {
                Some(c) => c.to_string(),
                None => "-".to_string(),
            };
            let _ = writeln!(out, "{cid}\t{lib}\t{cls}\t{nf}");
        }
        eprintln!(
            "{}",
            tr(
                lang,
                &format!("dae：命中 {} 个类", rows.len()),
                &format!("dae: {} classes", rows.len())
            )
        );
        emit(&o, &out, lang, "classes")
    })
}

// ---- functions ----
fn cmd_functions(args: &[String], lang: Lang, s: &Messages) -> Result<(), String> {
    let o = parse_opts(args, "functions", lang)?;
    let bin = o.bin("functions", lang)?;
    let pat = o.rest.first().cloned();
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let libs = filter_libs(&a.build_functions(true), &o.selection());
        let mut rows: Vec<(u64, u64, String, String, String)> = Vec::new();
        for (lib, cls_map) in &libs {
            for (cls, funcs) in cls_map {
                for e in funcs {
                    if let Some(p) = &pat {
                        let short = if cls.is_empty() {
                            e.mangled.clone()
                        } else {
                            format!("{cls}.{}", e.mangled)
                        };
                        if !(name_hit(p, &e.mangled, true)
                            || name_hit(p, &short, true)
                            || name_hit(p, cls, true))
                        {
                            continue;
                        }
                    }
                    let size = a.code_range(e.idx).map(|(_, s)| s).unwrap_or(0);
                    rows.push((
                        e.ep,
                        size,
                        lib.clone(),
                        cls.clone(),
                        e.mangled.clone(),
                    ));
                }
            }
        }
        rows.sort_by_key(|r| r.0);
        let mut out = String::new();
        for (ep, size, lib, cls, m) in rows.iter().take(limit_of(&o, usize::MAX)) {
            let _ = writeln!(out, "{ep:#x}\t{size}\t{lib}\t{cls}\t{m}");
        }
        eprintln!(
            "{}",
            tr(
                lang,
                &format!("dae：命中 {} 个函数（已列出 {}）", rows.len(), rows.len().min(limit_of(&o, usize::MAX))),
                &format!("dae: {} functions ({} listed)", rows.len(), rows.len().min(limit_of(&o, usize::MAX)))
            )
        );
        emit(&o, &out, lang, "functions")
    })
}

// ---- strings ----
fn cmd_strings(args: &[String], lang: Lang, s: &Messages) -> Result<(), String> {
    let o = parse_opts(args, "strings", lang)?;
    let bin = o.bin("strings", lang)?;
    let needle = o
        .find
        .clone()
        .or_else(|| o.rest.first().cloned())
        .map(|x| x.to_lowercase());
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let mut out = String::new();
        let mut hit = 0usize;
        let n = limit_of(&o, 200);
        let mut total = 0usize;
        for (r, v) in a.iso.strings.iter().chain(a.vm.strings.iter()) {
            let Some(text) = v.as_deref() else { continue };
            if let Some(nd) = &needle {
                if !text.to_lowercase().contains(nd) {
                    continue;
                }
            }
            total += 1;
            if hit < n {
                let _ = writeln!(out, "{r:#x}\t{text}");
                hit += 1;
            }
        }
        eprintln!(
            "{}",
            tr(
                lang,
                &format!("dae：命中 {total} 条（已列出 {hit}）"),
                &format!("dae: {total} strings ({hit} listed)")
            )
        );
        emit(&o, &out, lang, "strings")
    })
}

// ---- largest ----
fn cmd_largest(args: &[String], lang: Lang, s: &Messages) -> Result<(), String> {
    let o = parse_opts(args, "largest", lang)?;
    let bin = o.bin("largest", lang)?;
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let libs = filter_libs(&a.build_functions(true), &o.selection());
        let mut rows: Vec<(u64, u64, String)> = Vec::new();
        for (lib, cls_map) in &libs {
            for (cls, funcs) in cls_map {
                for e in funcs {
                    let size = a.code_range(e.idx).map(|(_, s)| s).unwrap_or(0);
                    let full = if cls.is_empty() {
                        format!("{lib}.{}", e.mangled)
                    } else {
                        format!("{lib}/{cls}.{}", e.mangled)
                    };
                    rows.push((size, e.ep, full));
                }
            }
        }
        rows.sort_by(|x, y| y.0.cmp(&x.0).then(x.1.cmp(&y.1)));
        let mut out = String::new();
        for (size, ep, full) in rows.iter().take(limit_of(&o, 20)) {
            let _ = writeln!(out, "{size}\t{ep:#x}\t{full}");
        }
        emit(&o, &out, lang, "largest")
    })
}

// ---- callers ----
#[cfg(feature = "asm")]
fn cmd_callers(args: &[String], lang: Lang, s: &Messages) -> Result<(), String> {
    let o = parse_opts(args, "callers", lang)?;
    let bin = o.bin("callers", lang)?;
    let target = o.rest.first().cloned();
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let libs = a.build_functions(true);
        let target = target.ok_or_else(|| {
            tr(lang, "callers：需要一个函数名或地址", "callers: needs a function name or address")
        })?;
        let at = if let Some(h) = target.strip_prefix("0x") {
            u64::from_str_radix(h, 16).ok()
        } else {
            None
        };
        let names = crate::export::callgraph::name_map(a, &libs);
        let edges = crate::export::callgraph::collect_edges(a, &libs);
        let mut rows: Vec<(u64, u64, String, u64, String)> = Vec::new();
        let mut indirect = 0usize;
        for e in &edges {
            let Some(to) = e.to else {
                indirect += 1;
                continue;
            };
            let hit = match at {
                Some(addr) => to == addr,
                None => {
                    let Some(n) = names.get(&to) else { continue };
                    // 名字匹配：全名（lib.Class.member）、Class.member、裸 member 都认
                    let short = n.rsplit('.').next().unwrap_or(n);
                    let tail2 = {
                        let mut it = n.rsplitn(3, '.');
                        let _m = it.next();
                        let c = it.next();
                        match c {
                            Some(c) => format!("{c}.{}", _m.unwrap_or("")),
                            None => n.clone(),
                        }
                    };
                    name_hit(&target, n, o.fuzzy)
                        || name_hit(&target, short, o.fuzzy)
                        || name_hit(&target, &tail2, o.fuzzy)
                }
            };
            if hit {
                let from = names
                    .get(&e.from)
                    .cloned()
                    .unwrap_or_else(|| format!("sub_{:#x}", e.from));
                let to_name = names.get(&to).cloned().unwrap_or_default();
                rows.push((e.at, e.from, from, to, to_name));
            }
        }
        // 去重：同一调用点在同一函数里可能被记多次（多入口指向同一函数体）
        rows.sort_by(|x, y| (x.0, x.1).cmp(&(y.0, y.1)));
        rows.dedup_by_key(|r| (r.0, r.1));
        let mut out = String::new();
        for (at, fep, from, to, to_name) in rows.iter().take(limit_of(&o, usize::MAX)) {
            let _ = writeln!(out, "{at:#x}\t{fep:#x}\t{from}\t->\t{to:#x}\t{to_name}");
        }
        eprintln!(
            "{}",
            tr(
                lang,
                &format!(
                    "dae：{} 个调用点指向它（另有 {indirect} 个间接调用目标运行时才可定，按设计未解析）",
                    rows.len()
                ),
                &format!(
                    "dae: {} call sites target it (plus {indirect} indirect calls, unresolved by design)",
                    rows.len()
                )
            )
        );
        emit(&o, &out, lang, "callers")
    })
}

// ---- disasm ----
#[cfg(feature = "asm")]
fn cmd_disasm(args: &[String], lang: Lang, s: &Messages) -> Result<(), String> {
    let o = parse_opts(args, "disasm", lang)?;
    let bin = o.bin("disasm", lang)?;
    let sel = target_sel(&o, "disasm", lang, TargetKind::Any)?;
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let all = a.build_functions(true);
        let picked = filter_libs(&all, &sel);
        if counts(&picked).2 == 0 {
            return Err(no_match("disasm", &sel, &all, lang));
        }
        let arm64 = a.platform.arch == "arm64";
        let cs = if arm64 { Some(crate::export::asm::build_cs()?) } else { None };
        let mut out = String::new();
        let mut n = 0usize;
        'outer: for (lib, cls_map) in &picked {
            for (cls, funcs) in cls_map {
                for e in funcs {
                    if n >= limit_of(&o, usize::MAX) {
                        break 'outer;
                    }
                    let Some((entry, csize)) = a.code_range(e.idx) else {
                        continue;
                    };
                    let foff = entry + a.slice_off;
                    let full = if cls.is_empty() {
                        format!("{lib}.{}", e.mangled)
                    } else {
                        format!("{lib}/{cls}.{}", e.mangled)
                    };
                    let _ = writeln!(out, "// {full}");
                    let _ = writeln!(
                        out,
                        "// {}: {entry:#x}, {}: {csize}",
                        tr(lang, "入口", "entry"),
                        tr(lang, "字节", "bytes")
                    );
                    let text = if let Some(cs) = &cs {
                        crate::export::asm::render_one(a, cs, &e.mangled, entry, csize, foff, entry)?
                    } else {
                        crate::decompiler::disasm_text(a, entry, csize, foff)?
                    };
                    out.push_str(&text);
                    n += 1;
                }
            }
        }
        emit(&o, &out, lang, "disasm")
    })
}

// ---- getclass / getmethod / getlib ----
#[cfg(feature = "asm")]
fn cmd_get(cmd: &str, args: &[String], lang: Lang, s: &Messages) -> Result<(), String> {
    let o = parse_opts(args, cmd, lang)?;
    let bin = o.bin(cmd, lang)?;
    let kind = match cmd {
        "getclass" => TargetKind::Class,
        "getmethod" => TargetKind::Func,
        _ => TargetKind::Lib,
    };
    let sel = target_sel(&o, cmd, lang, kind)?;
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let all = a.build_functions(true);
        let picked = filter_libs(&all, &sel);
        let (nl, nc, nf) = counts(&picked);
        if nf == 0 {
            return Err(no_match(cmd, &sel, &all, lang));
        }
        let (files, st) = crate::decompiler::render(a, &picked)?;
        // 输出：-o FILE.dart 单文件；-o DIR 走与全量导出同形的 dart/<库>.dart；
        // 无 -o / -o - 走 stdout（只出伪代码，不掺时间与统计，方便管道）
        match o.out.as_deref() {
            None | Some("-") => {
                let mut body = String::new();
                for (name, text) in &files {
                    let _ = writeln!(body, "// ===== {name} =====");
                    body.push_str(text);
                }
                print!("{body}");
            }
            Some(p) if p.ends_with(".dart") => {
                let mut body = String::new();
                for (_, text) in &files {
                    body.push_str(text);
                }
                if let Some(parent) = Path::new(p).parent() {
                    if !parent.as_os_str().is_empty() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                }
                std::fs::write(p, &body).map_err(|e| format!("{p}: {e}"))?;
                eprintln!(
                    "{}",
                    tr(
                        lang,
                        &format!("dae：已写出 {p}（{nf} 个函数）"),
                        &format!("dae: wrote {p} ({nf} functions)")
                    )
                );
            }
            Some(dir) => {
                let root = Path::new(dir).join("dart");
                std::fs::create_dir_all(&root).map_err(|e| format!("{}: {e}", root.display()))?;
                for (name, text) in &files {
                    std::fs::write(root.join(name), text).map_err(|e| format!("{name}: {e}"))?;
                }
                eprintln!(
                    "{}",
                    tr(
                        lang,
                        &format!("dae：已写出 {nl} 个库 / {nc} 个类 / {nf} 个函数到 {}", root.display()),
                        &format!("dae: wrote {nl} libs / {nc} classes / {nf} functions to {}", root.display())
                    )
                );
            }
        }
        if st.unmapped > 0 {
            eprintln!(
                "{}",
                tr(
                    lang,
                    &format!("dae：{} 行未映射指令（认不出的原样保留）", st.unmapped),
                    &format!("dae: {} unmapped instruction lines (kept verbatim)", st.unmapped)
                )
            );
        }
        Ok(())
    })
}

// 无 capstone 的构建（--no-default-features）：只读查询仍然可用，涉及反汇编的三个
// 命令明确报「本构建不含反汇编」，而不是给出错误结果。
#[cfg(not(feature = "asm"))]
fn cmd_callers(args: &[String], lang: Lang, s: &Messages) -> Result<(), String> {
    let _ = (args, s);
    Err(tr(lang, "callers：本构建未启用反汇编（capstone）", "callers: this build has no disassembler (capstone)"))
}

#[cfg(not(feature = "asm"))]
fn cmd_disasm(args: &[String], lang: Lang, s: &Messages) -> Result<(), String> {
    let _ = (args, s);
    Err(tr(lang, "disasm：本构建未启用反汇编（capstone）", "disasm: this build has no disassembler (capstone)"))
}

#[cfg(not(feature = "asm"))]
fn cmd_get(cmd: &str, args: &[String], lang: Lang, s: &Messages) -> Result<(), String> {
    let _ = (args, s);
    Err(tr(
        lang,
        &format!("{cmd}：本构建未启用反编译器（capstone）"),
        &format!("{cmd}: this build has no decompiler (capstone)"),
    ))
}

// ---------------------------------------------------------------- 帮助

fn help_for(cmd: &str, lang: Lang) -> String {
    let zh = matches!(lang, Lang::Zh);
    let t = |z: &str, e: &str| if zh { z.to_string() } else { e.to_string() };
    match cmd {
        "info" => format!(
            "{}\n\n  dae info <binary> [-o FILE]\n\n{}",
            t("info —— 快照、SDK 与规模概况（不落盘）", "info -- snapshot, SDK and size overview (writes nothing)"),
            t(
                "输出 TSV：容器 / 架构 / SDK / 状态 / 快照形态 / 指令段基址 / 指令表条目 /\n库 / 类 / 函数 / 字符串 / 对象数 / 告警数。",
                "TSV out: container / arch / SDK / status / snapshot form / instructions base /\ninstructions table entries / libraries / classes / functions / strings / objects / warnings."
            )
        ),
        "libs" => format!(
            "{}\n\n  dae libs <binary> [pattern] [-n N] [-o FILE]\n\n{}\n{}\n{}",
            t("libs —— 库（包）清单", "libs -- library (package) listing"),
            t("列：lib 名 \\t 类数 \\t 函数数 \\t 原始 URL（按函数数降序）", "columns: lib \\t classes \\t functions \\t source URL (sorted by function count)"),
            t("pattern 是子串匹配（库名与 URL 都试）；库名三种写法等价，见下。", "pattern is a substring match over both the lib name and its URL."),
            t("库名前缀即「按包」：--lib testing_app 选中 testing_app/*。", "A lib prefix means \"whole package\": --lib testing_app selects testing_app/*.")
        ),
        "classes" => format!(
            "{}\n\n  dae classes <binary> [pattern] [--lib P] [-n N] [-o FILE]\n\n{}\n{}",
            t("classes —— 类清单", "classes -- class listing"),
            t("列：cid \\t lib \\t 类名 \\t 函数数", "columns: cid \\t lib \\t class \\t functions"),
            t("pattern 子串匹配；--lib 限定库。", "pattern is a substring match; --lib narrows to a library.")
        ),
        "functions" => format!(
            "{}\n\n  dae functions <binary> [pattern] [--lib P] [--class P] [-n N] [-o FILE]\n\n{}\n{}",
            t("functions —— 函数清单", "functions -- function listing"),
            t("列：入口地址 \\t 字节数 \\t lib \\t 类 \\t 方法名", "columns: entry \\t bytes \\t lib \\t class \\t member"),
            t("pattern 可与方法名、Class.method 或类名匹配。", "pattern matches the member, Class.method or the class name.")
        ),
        "strings" => format!(
            "{}\n\n  dae strings <binary> [-f TEXT] [-n N] [-o FILE]\n\n{}",
            t("strings —— 快照字符串表检索（大小写不敏感子串）", "strings -- snapshot string table search (case-insensitive substring)"),
            t("列：对象 ref \\t 文本。默认最多列 200 条，-n 调整。", "columns: object ref \\t text. Lists at most 200 by default; -n changes it.")
        ),
        "largest" => format!(
            "{}\n\n  dae largest <binary> [-n N] [--lib P] [-o FILE]\n\n{}",
            t("largest —— 按代码字节数排前 N（默认 20）个函数", "largest -- top-N functions by code size (default 20)"),
            t("列：字节数 \\t 入口 \\t lib/类.方法。", "columns: bytes \\t entry \\t lib/Class.member.")
        ),
        "callers" => format!(
            "{}\n\n  dae callers <binary> <NAME|0xADDR> [--fuzzy] [-o FILE]\n\n{}\n{}",
            t("callers —— 谁调用了它（基于直接调用的静态边）", "callers -- who calls it (static direct-call edges)"),
            t("NAME 可写 lib/类.方法、类.方法或裸方法名；也可给 0x 地址。", "NAME may be lib/Class.member, Class.member, a bare member, or a 0x address."),
            t("间接调用（blr/call reg）目标运行时才定，按设计不解析，只在末尾报数量。", "Indirect calls (blr / call reg) resolve only at runtime and are not guessed; the count is reported.")
        ),
        "disasm" => format!(
            "{}\n\n  dae disasm <binary> <CLASS[.method]> [-o FILE]\n\n{}\n{}",
            t("disasm —— 单个函数（或一个类）的原始反汇编", "disasm -- raw disassembly of one function (or a whole class)"),
            t("arm64 带 blutter 同形的 IL 分组注释（与 asm/ 产物一致）；x64 为纯反汇编。", "arm64 includes the blutter-shaped IL group comments (same as the asm/ artifact); x64 is plain disassembly."),
            t("寄存器已按框架名替换（PP/THR/SP/FP…）。", "Registers are already renamed to framework roles (PP/THR/SP/FP...).")
        ),
        "getclass" | "getmethod" | "getlib" => {
            let (what, what_en) = match cmd {
                "getclass" => ("只反编译这一个类（含其方法）", "decompile just this class (with its methods)"),
                "getmethod" => ("只反编译这一个方法", "decompile just this method"),
                _ => ("只反编译这一个库（包）", "decompile just this library (package)"),
            };
            format!(
                "{}\n\n  dae {cmd} <binary> <NAME> [-o FILE.dart|-o DIR|-]\n\n{}\n{}\n{}",
                t(&format!("{cmd} —— {what}"), &format!("{cmd} -- {what_en}")),
                t("无 -o（或 -o -）→ 伪代码写 stdout，不掺统计，方便管道。", "No -o (or -o -) -> pseudocode to stdout, no stats mixed in, pipe-friendly."),
                t("-o 以 .dart 结尾 → 合并成单个文件；否则当成目录根，写出同形的 <DIR>/dart/<库>.dart。", "-o ending in .dart -> one merged file; otherwise treated as a directory root, writing <DIR>/dart/<lib>.dart."),
                t("没命中会给「是不是想找」提示（放宽为子串匹配）。", "On a miss, dae suggests near matches (relaxed to substring matching).")
            )
        }
        _ => help(lang),
    }
}

pub fn help(lang: Lang) -> String {
    let zh = matches!(lang, Lang::Zh);
    let t = |z: &str, e: &str| if zh { z.to_string() } else { e.to_string() };
    let mut h = String::new();
    let _ = writeln!(
        h,
        "{}",
        t(
            "渐进式用法：先查清单，再定点反编译某个类或库（不做全量导出）。",
            "Progressive usage: list first, then decompile one class or library (no full export)."
        )
    );
    let _ = writeln!(h);
    let _ = writeln!(h, "{}", t("先摸清全貌：", "Get oriented:"));
    let _ = writeln!(
        h,
        "  dae info      <binary>                        {}",
        t("快照 / SDK / 规模概况", "snapshot / SDK / size overview")
    );
    let _ = writeln!(
        h,
        "  dae libs      <binary> [pattern]              {}",
        t("库（包）清单 + 类数/函数数", "library (package) listing with counts")
    );
    let _ = writeln!(
        h,
        "  dae classes   <binary> [pattern] [--lib P]    {}",
        t("类清单", "class listing")
    );
    let _ = writeln!(
        h,
        "  dae functions <binary> [pattern] [--lib P]    {}",
        t("函数清单（入口 / 字节数 / 归属）", "function listing (entry / size / owner)")
    );
    let _ = writeln!(h);
    let _ = writeln!(h, "{}", t("找东西：", "Find things:"));
    let _ = writeln!(
        h,
        "  dae strings   <binary> [-f TEXT]              {}",
        t("字符串表检索", "string table search")
    );
    let _ = writeln!(
        h,
        "  dae largest   <binary> [-n N]                 {}",
        t("最大的 N 个函数", "top-N functions by size")
    );
    let _ = writeln!(
        h,
        "  dae callers   <binary> <NAME|0xADDR>          {}",
        t("谁调用了它", "who calls it")
    );
    let _ = writeln!(
        h,
        "  dae disasm    <binary> <CLASS[.method]>       {}",
        t("原始反汇编（arm64 带 IL 注释）", "raw disassembly (arm64 with IL comments)")
    );
    let _ = writeln!(h);
    let _ = writeln!(h, "{}", t("定点反编译：", "Decompile surgically:"));
    let _ = writeln!(
        h,
        "  dae getclass  <binary> <CLASS>                {}",
        t("单类", "one class")
    );
    let _ = writeln!(
        h,
        "  dae getmethod <binary> <CLASS.method>         {}",
        t("单方法", "one method")
    );
    let _ = writeln!(
        h,
        "  dae getlib    <binary> <LIB>                  {}",
        t("单库（包）", "one library (package)")
    );
    let _ = writeln!(h);
    let _ = writeln!(
        h,
        "{}",
        t(
            "通用选项：-o FILE 落盘（默认 stdout，-o - 也是），\n          -n N 限制条数，--lib/--class/--func 过滤（可重复），--fuzzy 放宽为子串，\n          --sdk-profile P / --platform-profile P 覆盖自动识别，-h 看子命令帮助。",
            "Common options: -o FILE to write (stdout by default; -o - is the same),\n          -n N to limit rows, --lib/--class/--func filters (repeatable), --fuzzy for substring\n          matching, --sdk-profile P / --platform-profile P to override detection, -h for per-command help."
        )
    );
    let _ = writeln!(h);
    let _ = writeln!(
        h,
        "{}",
        t(
            "全量或筛选导出（原有形态）：dae <binary> <out_dir> [--decompile] [--lib P] [--class P] [--func P]\n\
             命名口径：库名可写 functions.txt 的 lib 列（testing_app$screens$home）、libs.txt 的 URL\n\
             （package:testing_app/screens/home.dart）或产物文件名（testing_app_screens_home）；\n\
             库名支持前缀（--lib testing_app = 整个包）。类名默认精确，函数名可写 Class.method。\n\
             每条子命令都会重新解析一次快照（几十毫秒）——省下的是「不写全量产物」。",
            "Full or filtered export (the original form): dae <binary> <out_dir> [--decompile] [--lib P] [--class P] [--func P]\n\
             Naming: a library can be written as the lib column from functions.txt (testing_app$screens$home), the\n\
             URL from libs.txt (package:testing_app/screens/home.dart) or the artifact file name\n\
             (testing_app_screens_home); library names match by prefix (--lib testing_app = the whole package).\n\
             Class names are exact by default; function names may be written Class.method.\n\
             Every subcommand re-parses the snapshot (tens of milliseconds) -- what you save is not writing the full export."
        )
    );
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subcommand_detection() {
        assert!(is_subcommand("getclass"));
        assert!(is_subcommand("libs"));
        assert!(!is_subcommand("app.apk"));
        assert!(!is_subcommand("./info")); // 与本机文件同名时走全量导出
    }

    #[test]
    fn positional_parsing() {
        let lang = Lang::En;
        let args: Vec<String> = ["bin.so", "HomePage", "-n", "5", "--lib", "app"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let o = parse_opts(&args, "classes", lang).unwrap();
        assert_eq!(o.bin.as_deref(), Some("bin.so"));
        assert_eq!(o.rest, vec!["HomePage".to_string()]);
        assert_eq!(o.n, Some(5));
        assert_eq!(o.libs, vec!["app".to_string()]);
    }

    #[test]
    fn unknown_option_is_an_error() {
        let args: Vec<String> = ["bin.so", "--nope"].iter().map(|s| s.to_string()).collect();
        assert!(parse_opts(&args, "info", Lang::En).is_err());
    }
}