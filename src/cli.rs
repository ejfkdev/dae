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
use crate::args::{Cmd, Common, Query, Target};
use crate::locale::{Lang, Messages};
use crate::profile::{parse_platform, parse_sdk, PlatformProfile, SdkProfile};
use crate::export::textinfo::esc;
use crate::selection::{counts, filter_libs, name_hit, norm_lib, Selection};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

pub const SUBCOMMANDS: &[&str] = &[
    "export",
    "info",
    "libs",
    "classes",
    "functions",
    "strings",
    "fields",
    "largest",
    "pp",
    "objs",
    "stubs",
    "members",
    "callers",
    "callees",
    "findrefs",
    "disasm",
    "getclass",
    "getmethod",
    "getlib",
    "decompile",
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
    /// `--exclude-lib`（可重复）
    exclude_libs: Vec<String>,
    /// `--no-sdk`：排除 URL 以 `dart:` 开头的库
    no_sdk: bool,
    /// `--app`：排除 `dart:` 与 `package:flutter`
    app: bool,
    /// 位置参数（除 <binary> 与选项外的其余）
    rest: Vec<String>,
}

/// clap 的解析结果 → 内部统一的 [`Opts`]。
///
/// **所有命令共用这一处转换**，所以「某个 flag 被解析了却没传下去」这类 bug 在结构上
/// 不可能出现——参考项目 ddc 的 `callers` 就解析了 `--dex` 又在重建 argv 时把它丢了，
/// 于是 `callers x.dex foo -d 不存在的镜像` 照样返回结果而不报错。
fn opts_of(c: &Common, bin: String, rest: Vec<String>) -> Opts {
    Opts {
        bin: Some(bin),
        sdk: c.sdk_profile.clone(),
        platform: c.platform_profile.clone(),
        out: c.output.clone(),
        n: c.limit,
        find: c.find.clone(),
        libs: c.lib.clone(),
        classes: c.class.clone(),
        funcs: c.func.clone(),
        fuzzy: c.fuzzy,
        exclude_libs: c.exclude_lib.clone(),
        no_sdk: c.no_sdk,
        app: c.app,
        rest,
    }
}

/// `Opts` → `Selection`，并把 `--no-sdk` / `--app` 解析成**具体库名**再排除。
///
/// 这两个 flag 按库的**原始 URL 前缀**判（`dart:` / `package:flutter`），不按 mangled 名猜：
/// `library_name` 把 `dart:core` 写成 `dart_core`，一个叫 `dart_core_extra` 的包会长得很像。
///
/// 所有需要 Selection 的命令都走这一处，于是「某个命令解析了 flag 却悄悄忽略」在结构上
/// 不可能——参考项目 ddc 的 `callers` 就解析了 `--dex` 又在重建 argv 时丢掉。
fn resolve_selection(a: &Analyzer, o: &Opts) -> Selection {
    apply_scope(a, o, o.selection())
}

/// 把 `--no-sdk` / `--app` 解析出的排除库名并进一个**已有的** Selection。
///
/// 单独一个函数是因为 `getclass`/`disasm` 的 Selection 由 `target_sel` 在 `with_analyzer`
/// **之外**构造（那时还没有 Analyzer），只能在闭包里补这一步。
fn apply_scope(a: &Analyzer, o: &Opts, mut sel: Selection) -> Selection {
    let prefixes: &[&str] = if o.app {
        &["dart:", "package:flutter"]
    } else if o.no_sdk {
        &["dart:"]
    } else {
        &[]
    };
    if !prefixes.is_empty() {
        sel.exclude_libs.extend(a.lib_names_by_url_prefix(prefixes));
    }
    sel
}

/// `-h/--help` 走本项目自己的双语文本（写了输出列格式与命名口径），不是 clap 自动生成的。
/// 命中就直接退出 0——与手写解析器时代的行为一致。
fn maybe_help(c: &Common, cmd: &str, lang: Lang) {
    maybe_help2(c.help, cmd, lang);
}

/// `version` 没有共享选项组（它不接受任何参数），所以单独走这一个入口。
fn maybe_help2(flag: bool, cmd: &str, lang: Lang) {
    if flag {
        println!("{}", help_for(cmd, lang));
        std::process::exit(0);
    }
}

impl Opts {
    fn selection(&self) -> Selection {
        Selection {
            libs: self.libs.clone(),
            classes: self.classes.clone(),
            funcs: self.funcs.clone(),
            fuzzy: self.fuzzy,
            exclude_libs: self.exclude_libs.clone(),
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
    let a = Analyzer::new_located(&data, sdk, &platform, offs, used_fallback)?;
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

/// 失败分两类，因为**退出码不同**：`Run` 是运行期错误（1，`error: …` 走 stderr），
/// `Usage` 是用法错误（2，与 clap 自己的用法错误同码）。
///
/// 为什么用法错误要在这里出现而不全交给 clap：clap 的必填位置参数校验发生在解析阶段、
/// 早于 handler，于是 `dae libs -h` 会先撞上「required arguments were not provided」而以 2
/// 退出，`-h` 永远执行不到（18 个子命令全中）。所以位置参数在 `src/args.rs` 里声明成
/// `Option<String>`、由这里校验，`-h` 才有机会先跑（见 `maybe_help`）。
enum Fail {
    Run(String),
    Usage,
}

/// 取一个必填位置参数；缺失时印双语用法错误并返回 `Fail::Usage`。
///
/// 顺带修掉 clap 那条更难看的诊断：它把我们的 `-h` 当成一个名叫 `help` 的普通 flag，
/// 于是生成的 usage 行是 `dae libs --help <BINARY> [PATTERN]`，看起来像 `--help` 是必填项。
fn need(v: Option<String>, cmd: &str, arg: &str, lang: Lang, s: &Messages) -> Result<String, Fail> {
    match v {
        Some(x) => Ok(x),
        None => {
            eprintln!(
                "{}: {}",
                s.err_prefix,
                match lang {
                    Lang::Zh => {
                        format!("缺少参数 <{arg}>。用法见 `dae help {cmd}`；全部命令见 `dae help`")
                    }
                    Lang::En => {
                        format!("missing argument <{arg}>. Usage: see `dae help {cmd}`; all commands: `dae help`")
                    }
                }
            );
            Err(Fail::Usage)
        }
    }
}

/// 分派 clap 解析好的命令树。
///
/// 退出码口径与手写时代一致：**0 成功、1 运行期错误**（`error: …` 走 stderr）、
/// **2 用法错误**（clap 的解析错误在 `main` 里收尾，缺位置参数的在这里）。
pub fn run_cmd(cmd: Cmd, lang: Lang, s: &Messages) -> i32 {
    match dispatch(cmd, lang, s) {
        Ok(()) => 0,
        Err(Fail::Run(e)) => {
            eprintln!("{}: {e}", s.err_prefix);
            1
        }
        Err(Fail::Usage) => 2,
    }
}

/// 命令分派本体。抽出来是因为分派臂里要用 `?` 传播 `Fail`，而 `run_cmd` 返回的是退出码。
fn dispatch(cmd: Cmd, lang: Lang, s: &Messages) -> Result<(), Fail> {
    match cmd {
        Cmd::Version(v) => {
            maybe_help2(v.help, "version", lang);
            println!("dae {}", env!("GIT_VERSION"));
            Ok(())
        }
        Cmd::Help(h) => {
            // `dae help -h` 要给 help 自己的说明。没有这个 flag 时 `-h` 会被当成命令名，
            // 于是走进下面的「未知命令」分支报 2——22 条命令里唯一一条不支持 -h 的。
            maybe_help2(h.help, "help", lang);
            // 未知命令名按用法错误处理。以前这里无条件走 help_for 的兜底臂、把整份指南
            // 打出来并返回 0，于是 `dae help libss` 看起来像成功了——拼写错误被藏起来。
            if let Some(c) = h.cmd.as_deref() {
                if !is_subcommand(c) {
                    eprintln!(
                        "{}: {}",
                        s.err_prefix,
                        match lang {
                            Lang::Zh => format!(
                                "没有名为 {c} 的命令。有效命令：{}",
                                SUBCOMMANDS.join(" ")
                            ),
                            Lang::En => format!(
                                "no such command: {c}. Valid commands: {}",
                                SUBCOMMANDS.join(" ")
                            ),
                        }
                    );
                    return Err(Fail::Usage);
                }
            }
            println!(
                "{}",
                match h.cmd.as_deref() {
                    Some(c) => help_for(c, lang),
                    None => help(lang),
                }
            );
            Ok(())
        }
        Cmd::Export(a) => {
            maybe_help(&a.common, "export", lang);
            let bin = need(a.binary, "export", "binary", lang, s)?;
            let out = need(a.out_dir, "export", "out_dir", lang, s)?;
            let o = opts_of(&a.common, bin, Vec::new());
            cmd_export(o, &out, a.decompile, s).map_err(Fail::Run)
        }

        // 清单类：`<binary> [pattern]`
        Cmd::Info(a) => run_query(a, "info", lang, s, cmd_info),
        Cmd::Libs(a) => run_query(a, "libs", lang, s, cmd_libs),
        Cmd::Classes(a) => run_query(a, "classes", lang, s, cmd_classes),
        Cmd::Functions(a) => run_query(a, "functions", lang, s, cmd_functions),
        Cmd::Largest(a) => run_query(a, "largest", lang, s, cmd_largest),
        Cmd::Strings(a) => run_query(a, "strings", lang, s, cmd_strings),
        Cmd::Fields(a) => run_query(a, "fields", lang, s, cmd_fields),

        // 对象层：text/ 里那几个 dump 的查询入口（数据同源，见 ppobjs / stubs）
        Cmd::Pp(a) => run_query(a, "pp", lang, s, cmd_pp),
        Cmd::Objs(a) => run_query(a, "objs", lang, s, cmd_objs),
        Cmd::Stubs(a) => run_query(a, "stubs", lang, s, cmd_stubs),

        Cmd::Members(a) => {
            maybe_help(&a.common, "members", lang);
            let bin = need(a.binary, "members", "binary", lang, s)?;
            let rest = a.pattern.into_iter().collect();
            cmd_members(opts_of(&a.common, bin, rest), a.method, a.field, lang, s)
                .map_err(Fail::Run)
        }
        Cmd::Findrefs(a) => {
            maybe_help(&a.common, "findrefs", lang);
            let bin = need(a.binary, "findrefs", "binary", lang, s)?;
            let kind = need(a.kind, "findrefs", "string|kind", lang, s)?;
            let query = need(a.query, "findrefs", "query", lang, s)?;
            cmd_findrefs(opts_of(&a.common, bin, vec![kind, query]), lang, s).map_err(Fail::Run)
        }

        // 单目标类：`<binary> <name>`
        Cmd::Callers(a) => run_target(a, "callers", lang, s, cmd_callers),
        Cmd::Callees(a) => run_target(a, "callees", lang, s, cmd_callees),
        Cmd::Disasm(a) => run_target(a, "disasm", lang, s, cmd_disasm),
        Cmd::Getclass(a) => run_get(a, "getclass", lang, s),
        Cmd::Getmethod(a) => run_get(a, "getmethod", lang, s),
        Cmd::Getlib(a) => run_get(a, "getlib", lang, s),
        // 不复用 run_query：`decompile` 没有 pattern 位置参数（范围由 --lib/--no-sdk/--app
        // 决定）。若硬套 Query，`dae decompile bin foo` 会收下 foo 再静默忽略——正是要避免的。
        Cmd::Decompile(a) => {
            maybe_help(&a.common, "decompile", lang);
            let bin = need(a.binary, "decompile", "binary", lang, s)?;
            cmd_decompile(opts_of(&a.common, bin, Vec::new()), lang, s).map_err(Fail::Run)
        }
    }
}

type CmdFn = fn(Opts, Lang, &Messages) -> Result<(), String>;

fn run_query(a: Query, cmd: &'static str, lang: Lang, s: &Messages, f: CmdFn) -> Result<(), Fail> {
    maybe_help(&a.common, cmd, lang);
    let bin = need(a.binary, cmd, "binary", lang, s)?;
    let rest = a.pattern.into_iter().collect();
    f(opts_of(&a.common, bin, rest), lang, s).map_err(Fail::Run)
}

fn run_target(a: Target, cmd: &'static str, lang: Lang, s: &Messages, f: CmdFn) -> Result<(), Fail> {
    maybe_help(&a.common, cmd, lang);
    let bin = need(a.binary, cmd, "binary", lang, s)?;
    let name = need(a.name, cmd, "name", lang, s)?;
    f(opts_of(&a.common, bin, vec![name]), lang, s).map_err(Fail::Run)
}

fn run_get(a: Target, cmd: &'static str, lang: Lang, s: &Messages) -> Result<(), Fail> {
    maybe_help(&a.common, cmd, lang);
    let bin = need(a.binary, cmd, "binary", lang, s)?;
    let name = need(a.name, cmd, "name", lang, s)?;
    cmd_get(cmd, opts_of(&a.common, bin, vec![name]), lang, s).map_err(Fail::Run)
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

// ---- export（全量/筛选导出；也就是 `dae <binary> <out_dir>` 快捷形）----

/// 全量导出。摘要走 **stdout**（这是全量模式的人读通道，`tests/dart_valid.rs` 与
/// `tests/app_truth.rs` 都要解析其中 `dart/` 那一行的计数），告警与错误走 stderr。
/// 与子命令的口径相反——子命令 stdout 只放数据，见 [`emit`]。
fn cmd_export(o: Opts, out: &str, decompile: bool, s: &Messages) -> Result<(), String> {
    let bin = o.bin("export", s.lang)?;
    let sdk_override = o.sdk.as_deref();
    let platform_override = o.platform.as_deref();
    // --no-sdk / --app 要按库的原始 URL 判，得等有 Analyzer 才能解析（见 apply_scope）
    let mut sel = o.selection();
    let since = std::time::Instant::now();
    let bin_path = resolve_binary(bin, s)?;
    let data = std::fs::read(&bin_path)
        .map_err(|e| format!("{} {bin_path}: {e}", s.err_read_binary))?;
    if std::env::var("DART_AOT_TIMINGS").is_ok() {
        eprintln!("[timing] 读文件({} MB): {:?}", data.len() >> 20, since.elapsed());
    }

    // 平台 Profile：显式覆盖或按容器+架构自动选择（与渐进式子命令共用同一份逻辑）
    let platform: PlatformProfile = resolve_platform(&data, platform_override, s)?;

    // 快照偏移定位（自动识别与解析共用同一份结果）
    let (snap_offs, used_fallback) = crate::platform::locate_snapshots(&data, &platform)?;

    // SDK Profile：版本自动识别（hash 指纹 → 结构探针），--sdk-profile 强制覆盖
    let sdk_storage;
    let sdk: &SdkProfile = if let Some(p) = sdk_override {
        let c = std::fs::read_to_string(p).map_err(|e| format!("读 --sdk-profile: {e}"))?;
        sdk_storage = parse_sdk(&c)?;
        &sdk_storage
    } else {
        crate::profile::detect::detect_or_default(&data, snap_offs, s)
    };

    if sdk.status != "verified" {
        eprintln!(
            "{}: {} {} {}",
            s.warn_prefix, s.sdk_profile_label, sdk.abi, s.sdk_unverified
        );
    }
    println!(
        "{}: {} ({} {})",
        s.target_label, bin_path, platform.container.kind, platform.arch
    );
    let analyzer = Analyzer::new_located(&data, sdk, &platform, snap_offs, used_fallback)?;
    // 内部诊断（快照头/对象计数/指令表）：默认不刷屏，仅调试与回归时 DART_AOT_VERBOSE=1 展示
    if std::env::var("DART_AOT_VERBOSE").is_ok() {
        println!(
            "VM kinds={}  ISO kinds={} (kind={})",
            analyzer.vm.kind,
            analyzer.iso.kind,
            if analyzer.iso.kind == sdk.full_aot_kind { "FullAOT" } else { "?" }
        );
        println!(
            "VM: base_obj={} obj={} clusters={} instr_tbl_len={} rodata={:#x}",
            analyzer.vm.hdr.get("num_base_objects"),
            analyzer.vm.hdr.get("num_objects"),
            analyzer.vm.hdr.get("num_clusters"),
            analyzer.vm.hdr.get("instructions_table_len"),
            analyzer.vm.hdr.get("instructions_table_rodata_offset"),
        );
        println!(
            "ISO: base_obj={} obj={} clusters={} instr_tbl_len={} rodata={:#x}",
            analyzer.iso.hdr.get("num_base_objects"),
            analyzer.iso.hdr.get("num_objects"),
            analyzer.iso.hdr.get("num_clusters"),
            analyzer.iso.hdr.get("instructions_table_len"),
            analyzer.iso.hdr.get("instructions_table_rodata_offset"),
        );
        println!(
            "strings vm={} iso={} classes vm={} iso={} libs vm={} iso={} funcs vm={} iso={}",
            analyzer.vm.strings.len(),
            analyzer.iso.strings.len(),
            analyzer.vm.classes.len(),
            analyzer.iso.classes.len(),
            analyzer.vm.libraries.len(),
            analyzer.iso.libraries.len(),
            analyzer.vm.functions.len(),
            analyzer.iso.functions.len(),
        );
        println!(
            "InstructionsTable: first_entry_with_code={} n_entries={} instr_base(file-offset)={:#x} payload_infos={}",
            analyzer.first_entry,
            analyzer.pc_offsets.len(),
            analyzer.instr_base,
            analyzer.payload_infos.len()
        );
        // 覆盖率诊断：指令表里有多少条目能算出 (入口, 长度)，以及**已发布名字却没有函数体**的个数。
        //
        // 后者是本项目两次真实缺陷的共同指纹（`code_size` 的 `idx < first_entry` 旧守卫、
        // 以及 2.12–2.15 的 Instructions 去重导致「下一条」增量为 0），
        // 两次都表现为 functions.txt 名字齐全而 asm//dart/ 空空如也，
        // 且**任何形态指标都看不出来**（名字是对的）。门禁 tests/code_coverage.rs 直接断言它为 0。
        {
            let n = analyzer.pc_offsets.len();
            let withrange = (0..n).filter(|&i| analyzer.code_range(i).is_some()).count();
            let (mut pubfn, mut orphan) = (0usize, 0usize);
            for f in analyzer.iso.functions.values() {
                if let Some((_ep, idx)) = analyzer.entry_for(f.code_index) {
                    pubfn += 1;
                    if analyzer.code_range(idx).is_none() {
                        orphan += 1;
                    }
                }
            }
            println!(
                "code_range coverage: {withrange}/{n} entries; published_fns={pubfn} name_without_body={orphan}"
            );
        }
    }

    // 输出目录的绝对路径（不解析软链、不要求已存在，仅把相对路径接到 cwd 上），
    // 便于调用方/脚本直接复制取用最终产物位置。
    let out_abs = std::path::absolute(out)
        .map_err(|e| format!("解析输出目录绝对路径 {out}: {e}"))?;
    let out_display = out_abs.display().to_string();
    if std::env::var("DART_AOT_DEBUG_DEC").is_ok() {
        #[cfg(feature = "asm")]
        {
            crate::decompiler::pool_debug(&analyzer);
        }
    }
    sel = apply_scope(&analyzer, &o, sel);
    let filtered_libs = filter_libs(&analyzer.build_functions(true), &sel);
    if !sel.is_empty() {
        let (nl, nc, nf) = counts(&filtered_libs);
        if nf == 0 {
            return Err(format!(
                "{}（筛选后库 0 / 类 0 / 函数 0）",
                s.err_no_match
            ));
        }
        println!(
            "{}: {} {}, {} {}, {} {}",
            s.target_label, nl, s.sum_libs, nc, s.sum_classes, nf, s.sum_funcs
        );
    }
    // 解析漂移 = 快照布局与所选 Profile 不匹配（实测：移动端 product + compressed-pointers
    // 产物会漂成 libraries=1/classes=1）。此时**所有**产物都不可信，但对象池/字符串这类
    // 原始 dump 仍可人工核对，所以照常落盘、额外写一份 PARSE_DRIFT.txt，并以非零退出码收尾
    // ——让脚本和人都不会把垃圾当成结果。
    let drift: Vec<String> = analyzer
        .warnings
        .iter()
        .filter(|w| w.starts_with("!!! drift") || w.starts_with("!! alloc mismatch"))
        .cloned()
        .collect();

    let summary = crate::export::run_with(&analyzer, &out_abs, &sel)?;
    println!("{} {}:", s.export_done, out_display);
    println!("  r2_script/addNames.r2     {} {}", summary.r2_functions, s.sum_r2);
    println!("  ida_script/addNames.py    {} {}", summary.ida_functions, s.sum_ida);
    println!("  frida.js                  {} {}", summary.frida_classes, s.sum_frida);
    if summary.asm_enabled {
        println!("  asm/                      {} {}", summary.asm_functions, s.sum_asm);
    }
    println!("  text/pp.txt               {} {}", summary.pp_entries, s.sum_pp);
    println!("  text/objs.txt             {} {}", summary.objs_instances, s.sum_objs);
    println!("  text/strings.txt          {} {}", summary.textinfo.strings, s.sum_strings);
    println!("  text/libs.txt             {} {}", summary.textinfo.libs, s.sum_libs);
    println!("  text/classes.txt          {} {}", summary.textinfo.classes, s.sum_classes);
    println!("  text/functions.txt        {} {}", summary.textinfo.functions, s.sum_funcs);
    println!("  text/arrays.txt           {} {}", summary.textinfo.arrays, s.sum_arrays);
    println!("  text/maps.txt             {} {}", summary.textinfo.maps, s.sum_maps);
    if summary.textinfo.fields > 0 {
        println!("  text/fields.txt           {} {}", summary.textinfo.fields, s.sum_fields);
    }
    if let Some((total, named)) = summary.stubs {
        println!("  text/stubs.txt            {total} {}（{named} {}）", s.sum_stubs, s.sum_named);
    }
    if let Some((_f, d, dr, i)) = summary.callgraph {
        println!(
            "  call_edges.txt            {} {} + {} {}（{} {}）",
            d, s.sum_cg_d, i, s.sum_cg_i, dr, s.sum_cg_r
        );
    }

    if decompile {
        #[cfg(feature = "asm")]
        {
            let st = crate::decompiler::write(&analyzer, &filtered_libs, &out_abs)?;
            println!(
                "  dart/                     {} {} ({} {} / {} {}; {} {}, {} {}; {} {} {}; {} {}, {} {})",
                st.funcs,
                s.sum_dart,
                st.blocks,
                s.sum_blocks,
                st.stmts,
                s.sum_stmts,
                st.structured,
                s.sum_structured,
                st.fallback,
                s.sum_unstructured,
                st.unmapped,
                s.sum_unmapped,
                s.sum_lines,
                st.calls,
                s.sum_calls,
                st.calls_named,
                s.sum_named
            );
        }
        #[cfg(not(feature = "asm"))]
        eprintln!("note: --decompile needs the `asm` feature (capstone); rebuild with default features");
    }

    for w in &analyzer.warnings {
        eprintln!("{}: {w}", s.warn_prefix);
    }
    if let Ok(dump) = std::env::var("DART_AOT_DUMP_STRINGS") {
        let mut csv = String::new();
        for (k, v) in analyzer.iso.strings.iter() {
            let v = v.clone().unwrap_or_else(|| "<None>".to_string());
            csv.push_str(&format!("{k}\t{}\n", v.replace('\t', "\\t").replace('\n', "\\n")));
        }
        std::fs::write(&dump, csv).map_err(|e| format!("dump strings: {e}"))?;
        eprintln!("strings dumped to {dump}");
    }
    println!(
        "{} ({} {:.3}s)",
        s.done_label,
        s.elapsed_label,
        since.elapsed().as_secs_f64()
    );
    if !drift.is_empty() {
        let mut body = String::from(
            "Snapshot parse drifted: the SDK profile does not match this binary.\n\
             Every artifact in this directory was produced from a mismatched parse and must not be trusted.\n\
             The raw dumps (text/strings.txt, text/pp.txt) are still worth reading by hand.\n\n",
        );
        for w in &drift {
            body.push_str(w);
            body.push('\n');
        }
        body.push_str(
            "\nCommon cause: a mobile/Android build (features string contains `compressed-pointers`,\n\
             and often `dwarf_stack_traces_mode`) analyzed with a desktop profile.\n\
             Run `dae info <binary>` to see the detected SDK and the warnings, then pass an\n\
             explicit --sdk-profile if you have one for that build.\n",
        );
        let _ = std::fs::write(out_abs.join("PARSE_DRIFT.txt"), &body);
        eprintln!("{}", s.parse_drift_fatal);
        return Err(if s.lang == Lang::Zh {
            format!("快照解析漂移（{} 条告警）——产物不可信，详见 {}/PARSE_DRIFT.txt", drift.len(), out_abs.display())
        } else {
            format!("parse drifted ({} warnings) -- artifacts not trustworthy, see {}/PARSE_DRIFT.txt", drift.len(), out_abs.display())
        });
    }
    Ok(())
}

// ---- info ----
fn cmd_info(o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
    let bin = o.bin("info", lang)?;
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, false, |a, p, sdk| {
        let libs = a.build_functions(true);
        let (nl, nc, nf) = counts(&libs);
        let mut out = String::new();
        let _ = writeln!(out, "{}\t{}", tr(lang, "容器", "container"), p.container.kind);
        if let Some(fp) = a.fingerprint.as_ref() {
            // 构建开关（compressed-pointers / dwarf_stack_traces_mode）决定该配哪套 profile：
            // 移动端产物与桌面 profile 不匹配时，这一行就是第一现场
            let _ = writeln!(out, "{}\t{}", tr(lang, "features", "features"), fp.features);
        }
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
            "{}\t{:#x}",
            tr(lang, "指令段基址", "instructions base"),
            a.instr_base
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
            "{}\t{:?} / {:?}",
            tr(lang, "VM/ISO 对象", "VM/ISO objects"),
            a.vm.hdr.get("num_objects"),
            a.iso.hdr.get("num_objects")
        );
        let _ = writeln!(
            out,
            "{}\t{}",
            tr(lang, "告警", "warnings"),
            a.warnings.len()
        );
        emit(&o, &out, lang, "info")?;
        // 与全量导出同一条纪律：漂移时所有派生数字都不可信，退出码必须非零，
        // 否则脚本会把「libraries=1 / classes=1」的垃圾当成功结果收下。
        // info 的价值恰恰在于诊断，所以先把信息全部打印完，再以错误收尾。
        let drift = a
            .warnings
            .iter()
            .filter(|w| w.starts_with("!!! drift") || w.starts_with("!! alloc mismatch"))
            .count();
        if drift > 0 {
            return Err(tr(
                lang,
                &format!(
                    "解析漂移（{drift} 条）：上面的库/类/函数计数不可信。\
                     多半是快照布局与所选 profile 不匹配（自定义引擎、或版本/构建开关判定错了）"
                ),
                &format!(
                    "parse drift ({drift} entries): the library/class/function counts above are \
                     not trustworthy. Usually a snapshot layout that does not match the selected \
                     profile (custom engine, or a wrong version/build-flag match)"
                ),
            ));
        }
        Ok(())
    })
}

// ---- libs ----
fn cmd_libs(o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
    let bin = o.bin("libs", lang)?;
    let pat = o.rest.first().cloned();
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let libs = a.build_functions(true);
        // 库名 → 类数 / 函数数；同时给出 url（libs.txt 里的原始 URL）便于对上
        let url_of = |target: &str| -> String {
            for rec in a.iso.libraries.values() {
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
fn cmd_classes(o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
    let bin = o.bin("classes", lang)?;
    let pat = o.rest.first().cloned();
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let libs = filter_libs(&a.build_functions(true), &resolve_selection(a, &o));
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
        // 类名为空的那一组**不是类**，是该库的顶层函数（`build_functions` 把没有 owner
        // 类的函数归到空类名下）。在一条叫 `classes` 的命令里列出来是噪声，而且有害：
        // 空名按字典序**排在最前**，于是 `dae classes x | head -1 | cut -f3` 拿到空串
        // （实测就是这样把评估脚本打断的），计数也失真（本语料 300 行里 12 行是空名，
        // 而 text/classes.txt 是 544 条真 Class 记录——两个不同的集合）。
        // 跳过它们，但**如实报出跳过了多少**，不静默隐藏；顶层函数在 `dae functions`
        // （类列为空）与 `dae members` 里照常可见。
        let mut skipped_fn = 0usize;
        let mut skipped_libs = 0usize;
        for (lib, cls_map) in &libs {
            for (cls, funcs) in cls_map {
                if cls.is_empty() {
                    skipped_fn += funcs.len();
                    skipped_libs += 1;
                    continue;
                }
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
        // 计数必须说清口径：这里列的是**至少有一个函数**的类（走 build_functions），
        // 而 text/classes.txt 列的是**全部 Class 记录**。两者能差很多——实测 animations
        // 是 2177 vs 3358，差的 1181 个类的方法全被 AOT 内联/树摇了，只剩 Class 记录。
        // 不说清就会让人以为 dae 漏了三分之一的类（评估时我自己就被这个骗了一次）。
        let n_all = a.iso.classes.len();
        let skip_zh = if skipped_fn > 0 {
            format!("；另跳过 {skipped_libs} 个库的 {skipped_fn} 个顶层函数（没有所属类，见 dae functions）")
        } else {
            String::new()
        };
        let skip_en = if skipped_fn > 0 {
            format!("; also skipped {skipped_fn} top-level function(s) across {skipped_libs} librar(ies) -- they have no class, see dae functions")
        } else {
            String::new()
        };
        eprintln!(
            "{}",
            tr(
                lang,
                &format!(
                    "dae：命中 {} 个类（只含**有函数**的类；快照里共 {n_all} 条 Class 记录，其余的函数被内联/树摇，见 text/classes.txt）{skip_zh}",
                    rows.len()
                ),
                &format!(
                    "dae: {} classes (only those with at least one function; the snapshot has {n_all} Class records in all -- the rest had their methods inlined/tree-shaken, see text/classes.txt){skip_en}",
                    rows.len()
                )
            )
        );
        emit(&o, &out, lang, "classes")
    })
}

// ---- fields ----
/// 字段清单：Field 簇里**直接写着**的字段名（AOT 会丢掉 97–99%，这里只列剩下的）。
/// 偏移 = 字索引 × word_size；机器码里的位移比它小 1（tagged 折算）。
fn cmd_fields(o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
    let bin = o.bin("fields", lang)?;
    let pat = o.rest.first().cloned();
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let rows = a.field_rows();
        let mut out = String::new();
        let mut n = 0usize;
        let mut shown = 0usize;
        for r in &rows {
            if let Some(p) = &pat {
                if !name_hit(p, &r.class, true) && !name_hit(p, &r.name, true) {
                    continue;
                }
            }
            shown += 1;
            if n >= limit_of(&o, 200) {
                continue;
            }
            n += 1;
            let _ = writeln!(out, "{}\t{}\t{}\t{:#x}", r.class, r.name, r.source, r.off);
        }
        let n_rec = rows.iter().filter(|r| r.source == "rec").count();
        let n_acc = rows.len() - n_rec;
        eprintln!(
            "{}",
            tr(
                lang,
                &format!(
                    "dae：命中 {shown} 条具名字段（snapshot 保留 {n_rec} 条 + 访问器名推断 {n_acc} 条）"
                ),
                &format!(
                    "dae: {shown} named fields ({n_rec} from the snapshot + {n_acc} from accessor names)"
                )
            )
        );
        emit(&o, &out, lang, "fields")
    })
}

// ---- functions ----
fn cmd_functions(o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
    let bin = o.bin("functions", lang)?;
    let pat = o.rest.first().cloned();
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let libs = filter_libs(&a.build_functions(true), &resolve_selection(a, &o));
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
fn cmd_strings(o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
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
fn cmd_largest(o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
    let bin = o.bin("largest", lang)?;
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let libs = filter_libs(&a.build_functions(true), &resolve_selection(a, &o));
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

// ---- callers / callees ----

/// callers 与 callees 共用：按方向筛调用边、去重、排成 TSV。返回 `(正文, 行数, 间接调用数)`。
///
/// 两条命令只差「匹配哪一端」。名字匹配有四种口径（`0x` 地址、全名 `lib.Class.member`、
/// `Class.member`、裸 `member`），写成两份的话迟早只改一处——所以合成一份。
///
/// **两条命令都扫整个程序**，这是语义要求而不是省事：「谁调它」如果只在某个库里找，
/// 答案就是不完整的。因此 `--lib/--class/--func` 在这里**明确报错**，而不是像
/// 手写解析器时代那样解析了再静默忽略（参考项目 ddc 的 `callers` 就解析了 `--dex`
/// 又在重建 argv 时丢掉，于是 `--dex 不存在的镜像` 照样返回结果）。
#[cfg(feature = "asm")]
fn call_table(
    o: &Opts,
    a: &Analyzer,
    cmd: &str,
    target: &str,
    outgoing: bool,
    lang: Lang,
) -> Result<(String, usize, usize), String> {
    let sel = resolve_selection(a, o);
    if !sel.is_empty() {
        let (nl, nc, nf) = (
            sel.libs.len() + sel.exclude_libs.len(),
            sel.classes.len(),
            sel.funcs.len(),
        );
        // 这句问的是什么，取决于方向——先算好再进格式串（Rust 的格式串里没有内联条件）
        let what_zh = if outgoing { "它调谁" } else { "谁调它" };
        let what_en = if outgoing { "what it calls" } else { "who calls it" };
        return Err(tr(
            lang,
            &format!(
                "{cmd}：扫的是整个程序（否则「{what_zh}」就不完整），\
                 --lib/--class/--func 在这里没有意义（收到 {nl}/{nc}/{nf} 个）。 \
                 要按库看调用关系请用 text/call_edges.txt 或 callgraph.dot"
            ),
            &format!(
                "{cmd}: scans the whole program (otherwise \"{what_en}\" would be incomplete), so \
                 --lib/--class/--func do not apply here (got {nl}/{nc}/{nf}). \
                 For a per-library view use text/call_edges.txt or callgraph.dot"
            ),
        ));
    }
    let libs = a.build_functions(true);
    let at = target
        .strip_prefix("0x")
        .and_then(|h| u64::from_str_radix(h, 16).ok());
    let names = crate::export::callgraph::name_map(a, &libs);
    let edges = crate::export::callgraph::collect_edges(a, &libs);
    let mut rows: Vec<(u64, u64, String, u64, String)> = Vec::new();
    let mut indirect = 0usize;
    for e in &edges {
        let Some(to) = e.to else {
            indirect += 1;
            continue;
        };
        // callers 匹配被调方（to），callees 匹配调用方（from）
        let key = if outgoing { e.from } else { to };
        let hit = match at {
            Some(addr) => key == addr,
            None => {
                let Some(n) = names.get(&key) else { continue };
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
                name_hit(target, n, o.fuzzy)
                    || name_hit(target, short, o.fuzzy)
                    || name_hit(target, &tail2, o.fuzzy)
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
    rows.sort_by_key(|x| (x.0, x.1));
    rows.dedup_by_key(|r| (r.0, r.1));
    let n_rows = rows.len();
    let mut out = String::new();
    for (at, fep, from, to, to_name) in rows.iter().take(limit_of(o, usize::MAX)) {
        let _ = writeln!(out, "{at:#x}\t{fep:#x}\t{from}\t->\t{to:#x}\t{to_name}");
    }
    Ok((out, n_rows, indirect))
}

#[cfg(feature = "asm")]
fn cmd_callers(o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
    let bin = o.bin("callers", lang)?;
    let target = o.rest.first().cloned();
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let target = target.ok_or_else(|| {
            tr(lang, "callers：需要一个函数名或地址", "callers: needs a function name or address")
        })?;
        let (out, n_rows, indirect) = call_table(&o, a, "callers", &target, false, lang)?;
        eprintln!(
            "{}",
            tr(
                lang,
                &format!(
                    "dae：{n_rows} 个调用点指向它（另有 {indirect} 个间接调用目标运行时才可定，按设计未解析）"
                ),
                &format!(
                    "dae: {n_rows} call sites target it (plus {indirect} indirect calls, unresolved by design)"
                )
            )
        );
        emit(&o, &out, lang, "callers")
    })
}

/// `dae callees <bin> NAME|0xADDR`：它调了谁。列与 `callers` 完全相同，方便两边对着看。
///
/// 间接调用（`blr x8` / 寄存器 `call`）的目标运行时才可定，**按设计不解析**、也不进表，
/// 只在 stderr 的计数里说明有多少个——列出来就得给个目标，而给不出真的目标。
#[cfg(feature = "asm")]
fn cmd_callees(o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
    let bin = o.bin("callees", lang)?;
    let target = o.rest.first().cloned();
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let target = target.ok_or_else(|| {
            tr(lang, "callees：需要一个函数名或地址", "callees: needs a function name or address")
        })?;
        let (out, n_rows, indirect) = call_table(&o, a, "callees", &target, true, lang)?;
        eprintln!(
            "{}",
            tr(
                lang,
                &format!(
                    "dae：它调了 {n_rows} 个目标（另有 {indirect} 个间接调用目标运行时才可定，按设计未解析）"
                ),
                &format!(
                    "dae: it calls {n_rows} target(s) (plus {indirect} indirect calls, unresolved by design)"
                )
            )
        );
        emit(&o, &out, lang, "callees")
    })
}

#[cfg(not(feature = "asm"))]
fn cmd_callees(o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
    let _ = (o, s);
    Err(tr(
        lang,
        "callees：本构建未启用反汇编（capstone）",
        "callees: this build has no disassembler (capstone)",
    ))
}

// ---- pp / objs / stubs（对象层查询）----
//
// 三条命令的数据都与 `text/` 里的同名产物**同源**：描述文本走 `ppobjs::pp_describe`、
// 候选实例走 `ppobjs::obj_candidates`、stub 行走 `stubs::stub_rows`。
// 所以「在产物里看到的」与「查出来的」不可能是两套东西——这不是约定，是同一份代码。

/// `dae pp <bin> [pattern]`：对象池条目。三列 `offset \t kind \t value`。
///
/// 池条目是反编译输出里 `x0 = "Hello" /* pp+0x17f8 */` 那个偏移的落点，
/// 也是 `dae findrefs` 的检索面。
fn cmd_pp(o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
    let bin = o.bin("pp", lang)?;
    let pat = o.rest.first().map(|p| p.to_lowercase());
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let Some(entries) = a.iso.objectpool_entries.as_ref() else {
            return Err(tr(
                lang,
                "pp：这个快照没有 ObjectPool 条目",
                "pp: this snapshot has no ObjectPool entries",
            ));
        };
        let limit = limit_of(&o, 200);
        let mut out = String::new();
        let (mut shown, mut n) = (0usize, 0usize);
        for (i, ent) in entries.iter().enumerate() {
            let mut val = String::new();
            let kind = crate::export::ppobjs::pp_describe(a, &mut val, ent);
            if let Some(p) = &pat {
                if !val.to_lowercase().contains(p) {
                    continue;
                }
            }
            shown += 1;
            if n >= limit {
                continue;
            }
            n += 1;
            // 值本身就是字符串字面量，带 tab/换行是常态 → 必须转义，否则 TSV 列数会错
            let _ = writeln!(
                out,
                "{:#x}\t{}\t{}",
                crate::export::ppobjs::pp_offset(i),
                kind,
                esc(&val)
            );
        }
        eprintln!(
            "{}",
            tr(
                lang,
                &format!("dae：命中 {shown} 个池条目（全表 {} 个）", entries.len()),
                &format!("dae: {shown} pool entries matched (of {} in the pool)", entries.len())
            )
        );
        emit(&o, &out, lang, "pp")
    })
}

/// `dae objs <bin> [pattern]`：用户类实例（含字段值）。
///
/// 输出是**块**而不是 TSV——与 `text/objs.txt` 同形（`instance_block` 是多行的递归 dump），
/// 硬压成一行反而没法读。判据也与产物同一个：只有真解出实例块的（`Obj!` 开头）才算。
fn cmd_objs(o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
    let bin = o.bin("objs", lang)?;
    let pat = o.rest.first().map(|p| p.to_lowercase());
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let cands = crate::export::ppobjs::obj_candidates(a);
        let limit = limit_of(&o, 20);
        let mut out = String::new();
        let (mut shown, mut n) = (0usize, 0usize);
        for &r in &cands {
            let Some((cid, _)) = a.iso.instance_fields.get(&r) else {
                continue;
            };
            let block = crate::export::ppobjs::instance_block(a, r, *cid, 0);
            if !block.starts_with("Obj!") {
                continue;
            }
            if let Some(p) = &pat {
                if !block.to_lowercase().contains(p) {
                    continue;
                }
            }
            shown += 1;
            if n >= limit {
                continue;
            }
            n += 1;
            out.push_str(&block);
            out.push_str("\n\n");
        }
        eprintln!(
            "{}",
            tr(
                lang,
                &format!("dae：命中 {shown} 个实例（候选 {} 个）", cands.len()),
                &format!("dae: {shown} instances matched (of {} candidates)", cands.len())
            )
        );
        emit(&o, &out, lang, "objs")
    })
}

/// `dae stubs <bin> [pattern]`：指令表里没有被任何 Function 对象引用的条目。
/// 三列 `entry \t bytes \t name`。
///
/// ⚠️ 口径是「没被 Function 引用」而**不是**「没有 Code 对象」——dae 不检查后者，
/// 而且 SDK 源码（`app_snapshot.cc`）表明每条表项都对应一个 Code 对象，
/// 只是 `first_entry_with_code` 之前那些的 Code 被**丢弃**了（入口点照样保留）。
/// 它们也**不全是 stub**：见 `export/stubs.rs` 顶部与 docs/DECOMPILER.md。
///
/// 名字解不出就是空——**绝不为凑覆盖率编名字**（口径见 `export/stubs.rs` 的模块文档，
/// 门禁 `alloc_stub_naming` 盯着）。
fn cmd_stubs(o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
    let bin = o.bin("stubs", lang)?;
    let pat = o.rest.first().map(|p| p.to_lowercase());
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let rows = crate::export::stubs::stub_rows(a);
        let limit = limit_of(&o, 200);
        let mut out = String::new();
        let (mut shown, mut n, mut named) = (0usize, 0usize, 0usize);
        for (ep, size, name) in &rows {
            if let Some(p) = &pat {
                if !name.to_lowercase().contains(p) {
                    continue;
                }
            }
            shown += 1;
            if !name.is_empty() {
                named += 1;
            }
            if n >= limit {
                continue;
            }
            n += 1;
            let _ = writeln!(out, "{ep:#x}\t{size}\t{}", esc(name));
        }
        eprintln!(
            "{}",
            tr(
                lang,
                &format!("dae：命中 {shown} 条（其中 {named} 条解出了名字；解不出的留空，不编）"),
                &format!(
                    "dae: {shown} matched ({named} with a resolved name; the rest stay empty, not invented)"
                )
            )
        );
        emit(&o, &out, lang, "stubs")
    })
}

// ---- members ----

/// `dae members <bin> [NAME] [--class X] [--method|--field]`：方法与字段的统一名字检索。
/// 四列 `kind \t class \t member \t detail`；detail 对方法是入口地址、对字段是 `来源:偏移`。
///
/// **一处有意的不对称，写在 help 里而不是悄悄吞掉**：`--lib` 只作用于方法。
/// 字段行（`Analyzer::field_rows`）在快照里没有库归属——`Field` 簇给的是类、名、偏移，
/// 库要再经 `类 → ClassRec → library_ref` 一跳才拿得到，而那一跳对「按名字找字段」没有帮助。
/// 与其让 `--lib` 对字段静默无效，不如明说。
fn cmd_members(
    o: Opts,
    only_method: bool,
    only_field: bool,
    lang: Lang,
    s: &Messages,
) -> Result<(), String> {
    let bin = o.bin("members", lang)?;
    let pat = o.rest.first().map(|p| p.to_lowercase());
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let limit = limit_of(&o, 200);
        let mut out = String::new();
        let (mut shown, mut n) = (0usize, 0usize);
        let (mut n_m, mut n_f) = (0usize, 0usize);

        if !only_field {
            let libs = a.build_functions(true);
            let libs = filter_libs(&libs, &resolve_selection(a, &o));
            for (_lib, cls_map) in &libs {
                for (cls, funcs) in cls_map {
                    for f in funcs {
                        if let Some(p) = &pat {
                            if !f.mangled.to_lowercase().contains(p)
                                && !cls.to_lowercase().contains(p)
                            {
                                continue;
                            }
                        }
                        shown += 1;
                        n_m += 1;
                        if n >= limit {
                            continue;
                        }
                        n += 1;
                        let _ = writeln!(
                            out,
                            "method\t{}\t{}\t{:#x}",
                            esc(cls),
                            esc(&f.mangled),
                            f.ep
                        );
                    }
                }
            }
        }
        if !only_method {
            let cls_pat = o.classes.first().cloned();
            for r in a.field_rows() {
                if let Some(c) = &cls_pat {
                    if !name_hit(c, &r.class, o.fuzzy) {
                        continue;
                    }
                }
                if let Some(p) = &pat {
                    if !r.name.to_lowercase().contains(p) && !r.class.to_lowercase().contains(p) {
                        continue;
                    }
                }
                shown += 1;
                n_f += 1;
                if n >= limit {
                    continue;
                }
                n += 1;
                let _ = writeln!(
                    out,
                    "field\t{}\t{}\t{}:{:#x}",
                    esc(&r.class),
                    esc(&r.name),
                    r.source,
                    r.off
                );
            }
        }
        eprintln!(
            "{}",
            tr(
                lang,
                &format!("dae：命中 {shown} 个成员（方法 {n_m} + 字段 {n_f}）"),
                &format!("dae: {shown} members matched ({n_m} methods + {n_f} fields)")
            )
        );
        emit(&o, &out, lang, "members")
    })
}

// ---- hierarchy：本轮不提供 ----
//
// 原本计划加 `dae hierarchy <bin> CLASS`（extends 上行链 + 直接子类）。**做出来了，但撤掉了**，
// 因为它给的答案是错的，而错的继承链比没有继承链更糟。
//
// 证据（material_3_demo，源码就在 /Users/e/Documents/github/flutter-samples 可对照）：
//   真值 `App extends StatefulWidget`        → parent_of 给 SceneBuilder（cid 1142）
//   真值 `BrightnessButton extends StatelessWidget` → parent_of 给 ParagraphBuilder
//   真值 `_AppState extends State<App>`      → parent_of 给 _MixinApplication163&…
// 而同一批数据里 **`self` 行的类名与库全对**（cid → 名字这一跳是好的），坏的只有 super 这一跳。
//
// 定位到这一步：Class 簇 13 个 ref 里只有位置 9（当前当作 super_type_ref）与位置 11
// 能在 `type_cids` 里解出 cid，其余 11 个都不是 Type 对象的 ref；把别名挪到 11 得到
// `_WindowControllerMixin`，对 `App` 同样是错的。所以要么 super 不在这 13 个 ref 里，
// 要么 Type 簇的 `type_class_id=(flags>>4)&cid_tag_mask` 这个解码不对——两者都要对着
// Dart SDK 源码核，并重验 47 份 profile 与 25 份对拍存档，是独立的一轮工作。
//
// ⚠️ 连带影响（**已发布产物里的既有问题，不是本轮引入**）：同一个 `parent_of` 还喂给
// `frida.js` 的 `sid` 字段与 `ppobjs::instance_block` 的祖先字段分组，所以那两处现在也是错的
// （实测 frida.js：App sid=1142 而真父类是 2285）。见 analyzer.rs 里 `sid` 处的注释。
// ---- findrefs ----

/// `dae findrefs <bin> <kind> <query>`：哪些代码位置从对象池里加载了这个字面量/类型。
/// 五列 `at \t from_ep \t from \t pp_offset \t value`。
///
/// **零编造判据**：偏移解析走的是 `decompiler::PoolRefs`，与反编译产物里
/// `x0 = "Hello" /* pp+0x17f8 */` 那条注释**同一份代码**（`mask_regs` + `mem_parts` +
/// `pool_key`）。所以「findrefs 报出的每个命中都能在 dart/ 里找到对应的 `/* pp+0x… */`」
/// 是可断言的，门禁 `tests/cli_query.rs` 就断言这条。
///
/// **只支持 `string` 与 `type`，不支持 `field`**：编译后的机器码里没有符号化的字段引用，
/// 只剩裸位移，按位移匹配会把大量无关的 `[x, #0x18]` 报成命中——那是猜，不是查。
#[cfg(feature = "asm")]
fn cmd_findrefs(o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
    let bin = o.bin("findrefs", lang)?;
    let kind = o
        .rest
        .first()
        .cloned()
        .ok_or_else(|| tr(lang, "findrefs：需要 kind（string 或 type）", "findrefs: needs a kind (string or type)"))?;
    let query = o
        .rest
        .get(1)
        .cloned()
        .ok_or_else(|| tr(lang, "findrefs：需要查询文本", "findrefs: needs a query"))?;
    // kind 只有两种，都是**可证**的检索面：
    //   string TEXT —— 池里的字符串字面量（内容可读，按子串搜）
    //   kind   NAME —— 池里对象种类恰为 NAME 的条目（就是 dart/ 里 `/* TypeArguments */` 那个词）
    // 不提供 `field`：编译后的机器码里没有符号化的字段引用，只剩裸位移，按位移匹配会把
    // 大量无关的 [x, #0x18] 报成命中——那是猜，不是查。
    // 也不提供 `type`：池条目的描述形是 `Kind: 内容`，那个前缀是**对象类别**而不是类型名，
    // 拿它当类型名检索会既漏又误（搜 Field 命中的是所有 Field 对象，与具体哪个字段无关）。
    if kind != "string" && kind != "kind" {
        return Err(tr(
            lang,
            &format!(
                "findrefs：不支持的 kind「{kind}」。只支持 `string TEXT`（池里的字符串字面量）\
                 与 `kind NAME`（对象种类，即 dart/ 里 /* X */ 那个词）。\
                 不提供 field：编译后没有符号化的字段引用，只剩裸位移，按位移匹配会把大量\
                 无关的 [x, #0x18] 报成命中——那是猜不是查"
            ),
            &format!(
                "findrefs: unsupported kind \"{kind}\". Only `string TEXT` (pool string literals) \
                 and `kind NAME` (object kind, i.e. the /* X */ word in dart/). \
                 There is no `field`: compiled code carries no symbolic field reference, just a bare \
                 displacement, so matching on displacement would report unrelated [x, #0x18] as hits"
            ),
        ));
    }
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let pr = crate::decompiler::PoolRefs::new(a);
        let targets: std::collections::BTreeMap<u64, String> = if kind == "string" {
            pr.values_containing(&query)
                .into_iter()
                .filter(|(_, _, is_str)| *is_str)
                .map(|(off, v, _)| (off, v))
                .collect()
        } else {
            pr.entries_of_kind(&query).into_iter().collect()
        };
        if targets.is_empty() {
            // 没命中就给可操作的提示：列出池里真实存在过的种类，而不是只说"没有"
            let ks: Vec<String> = pr.kinds().iter().take(8).map(|(k, n)| format!("{k}({n})")).collect();
            return Err(tr(
                lang,
                &format!(
                    "findrefs：对象池里没有匹配的条目（池共 {} 条）。\
                     `kind` 可用的种类有：{}",
                    pr.len(),
                    ks.join(", ")
                ),
                &format!(
                    "findrefs: no matching pool entry (pool has {} entries). \
                     Available kinds for `findrefs kind NAME`: {}",
                    pr.len(),
                    ks.join(", ")
                ),
            ));
        }
        let libs = a.build_functions(true);
        let plan = crate::export::callgraph::plan_functions(a, &libs);
        let mut hits = crate::disasm::scan_instructions(a, &plan, |f, ins| {
            let ops = ins.op_str()?;
            let off = pr.offset_in_operand(ops)?;
            let v = targets.get(&off)?;
            Some((ins.address(), f.ep, f.name.to_string(), off, v.clone()))
        })?;
        // 按地址排序并去重：同一条指令可能被扫到一次以上（共享代码块）
        hits.sort_by_key(|h| (h.0, h.3));
        hits.dedup_by_key(|h| (h.0, h.3));
        let total = hits.len();
        let mut out = String::new();
        for (at, fep, from, off, v) in hits.iter().take(limit_of(&o, usize::MAX)) {
            let _ = writeln!(out, "{at:#x}\t{fep:#x}\t{}\t{off:#x}\t{}", esc(from), esc(v));
        }
        eprintln!(
            "{}",
            tr(
                lang,
                &format!(
                    "dae：{total} 处代码加载它（池里 {} 个条目命中查询；扫描 {} 个函数）",
                    targets.len(),
                    plan.len()
                ),
                &format!(
                    "dae: {total} code sites load it ({} pool entries matched the query; scanned {} functions)",
                    targets.len(),
                    plan.len()
                )
            )
        );
        emit(&o, &out, lang, "findrefs")
    })
}

#[cfg(not(feature = "asm"))]
fn cmd_findrefs(o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
    let _ = (o, s);
    Err(tr(
        lang,
        "findrefs：本构建未启用反汇编（capstone）",
        "findrefs: this build has no disassembler (capstone)",
    ))
}

// ---- disasm ----
#[cfg(feature = "asm")]
fn cmd_disasm(o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
    let bin = o.bin("disasm", lang)?;
    // 位置参数若是 `0x…` 形式的地址，走「按地址反汇编」。
    //
    // 这是必需的：占调用目标 **54%** 的是未命名 stub（material_3_demo 实测 42759 个
    // `sub_0x…()` 调用点、只有 **346 个不同地址**，其中 89.8% 在 stub 表里、没有 Function 引用），
    // 而 stub 从不出现在 `build_functions` 里 ⇒ 按名字的路径**结构上就够不到它们**，
    // 于是产物里最该看的那部分代码根本没法查看。
    //
    // 长度只从**函数表或 stub 表**取；两个表都没有就报错，**绝不猜一个窗口长度**
    // （猜长度会反汇编到别的代码上去，而输出看起来完全正常——这类错位本项目踩过三次）。
    if let Some(addr) = o.rest.first().and_then(|t| {
        let h = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X"))?;
        if h.is_empty() || !h.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        u64::from_str_radix(h, 16).ok()
    }) {
        return with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
            // 1) 函数入口
            let mut found: Option<(u64, u64, String)> = None;
            for &(_, idx) in a.func_eps.values() {
                if let Some((ep, csize)) = a.code_range(idx) {
                    if ep == addr {
                        found = Some((ep, csize, format!("function@{ep:#x}")));
                        break;
                    }
                }
            }
            // 2) stub 表条目（无 Code 对象；名字可能是空的）
            if found.is_none() {
                for (ep, size, name) in crate::export::stubs::stub_rows(a) {
                    if ep == addr {
                        let label = if name.is_empty() {
                            format!("stub@{ep:#x}")
                        } else {
                            name
                        };
                        found = Some((ep, size, label));
                        break;
                    }
                }
            }
            // 3) 子 stub：一个表项里装着多个 32 字节变体（写屏障族），调用方直接 bl 到
            //    条目**内部**地址。窗口不是猜的——形状校验要求恰好 8 条指令 = 32 字节，
            //    且该表项的**每一个** 32 字节块都通过同一校验才认（见 write_barrier_sub_stubs）。
            if found.is_none() {
                if let Some(name) = crate::export::callgraph::write_barrier_sub_stubs(a).get(&addr) {
                    found = Some((addr, 32, name.clone()));
                }
            }
            let Some((entry, csize, label)) = found else {
                return Err(tr(
                    lang,
                    &format!(
                        "disasm: {addr:#x} 既不是函数入口、也不在 stub 表里；不猜窗口长度（猜长度会反汇编到别的字节上，而输出看起来完全正常）"
                    ),
                    &format!(
                        "disasm: {addr:#x} is neither a function entry nor a stub-table entry; not guessing a window (a guessed length disassembles unrelated bytes and still looks plausible)"
                    ),
                ));
            };
            let (foff, _) = crate::disasm::function_code(a.data, a.slice_off, entry, csize)
                .ok_or_else(|| "字节超出文件范围".to_string())?;
            let mut out = String::new();
            let _ = writeln!(out, "// {label}");
            let _ = writeln!(
                out,
                "// {}: {entry:#x}, {}: {csize}",
                tr(lang, "入口", "entry"),
                tr(lang, "字节", "bytes")
            );
            let text = if a.platform.arch == "arm64" {
                let cs = crate::disasm::build_cs(true)?;
                crate::export::asm::render_one(a, &cs, &label, entry, csize, entry)?
            } else {
                crate::decompiler::disasm_text(a, entry, csize, foff)?
            };
            out.push_str(&text);
            emit(&o, &out, lang, "disasm")
        });
    }
    let sel = target_sel(&o, "disasm", lang, TargetKind::Any)?;
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let sel = apply_scope(a, &o, sel);
        let all = a.build_functions(true);
        let picked = filter_libs(&all, &sel);
        if counts(&picked).2 == 0 {
            return Err(no_match("disasm", &sel, &all, lang));
        }
        let arm64 = a.platform.arch == "arm64";
        let cs = if arm64 { Some(crate::disasm::build_cs(true)?) } else { None };
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
                    // 防回绕：见 crate::disasm::function_code
                    let (foff, _) = crate::disasm::function_code(a.data, a.slice_off, entry, csize)
                        .ok_or_else(|| "函数字节超出文件范围".to_string())?;
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
                        crate::export::asm::render_one(a, cs, &e.mangled, entry, csize, entry)?
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
fn cmd_get(cmd: &str, o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
    let bin = o.bin(cmd, lang)?;
    let kind = match cmd {
        "getclass" => TargetKind::Class,
        "getmethod" => TargetKind::Func,
        _ => TargetKind::Lib,
    };
    let sel = target_sel(&o, cmd, lang, kind)?;
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let sel = apply_scope(a, &o, sel);
        let all = a.build_functions(true);
        let picked = filter_libs(&all, &sel);
        let (nl, nc, nf) = counts(&picked);
        if nf == 0 {
            return Err(no_match(cmd, &sel, &all, lang));
        }
        let (files, st) = crate::decompiler::render(a, &picked)?;
        emit_decompiled(&o, &files, &st, (nl, nc, nf), lang)
    })
}

/// 把 `render` 的多份「前导 + 正文」合并成 `(单份前导, 带分隔符的正文)`。
///
/// 单库时**逐字节**返回原样（前导本来就是对的），保证改前改后对单库目标的输出完全一致；
/// 多库时才重算前导。分隔符 `// ===== <库文件名> =====` 与 stdout 既有格式一致。
/// `with_separators`：stdout 走 `true`（既有格式是「每文件一段 `// ===== 名字 =====`」，
/// 这个契约要保住）；`-o FILE.dart` 走 `false`（落盘文件靠正文里的 `// library: X` 区分，
/// 且单库时必须与原样逐字节一致，才能和全量导出的 `<库>.dart` 对得上）。
///
/// ⚠️ 分隔符的位置相对旧实现**变了**：旧的是「分隔符 → 前导 → 正文」，于是命中多库时
/// 前导被重复了 N 份（`mem`/`memSet` 重复定义 ⇒ 产物非法）。合法的单份前导只能放在
/// 最前面，所以现在是「前导 → (分隔符 → 正文) × N」。
#[cfg(feature = "asm")]
fn merge_rendered(files: &[(String, String)], with_separators: bool) -> (String, String) {
    use crate::decompiler::{dart_preamble_for, split_rendered};
    // 单库且不要分隔符：逐字节原样返回（改前改后完全一致）
    if files.len() <= 1 && !with_separators {
        return match files.first() {
            Some((_, text)) => match split_rendered(text) {
                Some((pre, body)) => (pre.to_string(), body.to_string()),
                None => (String::new(), text.clone()),
            },
            None => (String::new(), String::new()),
        };
    }
    let mut bodies = String::new();
    for (name, text) in files {
        let body = match split_rendered(text) {
            Some((_, b)) => b,
            // 找不到标记就原样保留（不猜、不丢内容）
            None => text.as_str(),
        };
        if with_separators {
            let _ = writeln!(bodies, "// ===== {name} =====");
        }
        bodies.push_str(body);
    }
    // 单库时前导本来就是对的，不必重算（也保证与全量导出逐字节一致）
    if files.len() == 1 {
        if let Some((_, text)) = files.first() {
            if let Some((pre, _)) = split_rendered(text) {
                return (pre.to_string(), bodies);
            }
        }
    }
    (dart_preamble_for(&bodies), bodies)
}

/// `getclass` / `getmethod` / `getlib` / `decompile` 共用的输出路由：
/// * 无 `-o` 或 `-o -` → **stdout**，每文件一段 `// ===== name =====`，不掺时间与统计（可管道）；
/// * `-o FILE.dart` → 合并成单文件；
/// * `-o DIR` → 当作目录，写 `<DIR>/dart/<库>.dart`，与全量导出**同形**。
///
/// 四条命令一份实现：`decompile` 与 `get*` 的差别只在 Selection 是「全部」还是「一个目标」，
/// 落盘形态没有任何理由不同（分成两份的话，改一处忘一处就会让 `getlib X -o DIR` 与
/// `decompile --lib X -o DIR` 产出不同的目录布局）。
#[cfg(feature = "asm")]
fn emit_decompiled(
    o: &Opts,
    files: &[(String, String)],
    st: &crate::decompiler::DecompileStats,
    (nl, nc, nf): (usize, usize, usize),
    lang: Lang,
) -> Result<(), String> {
    match o.out.as_deref() {
        None | Some("-") => {
            // 多库合并时前导只能有**一份**，否则占位函数重复定义、产物过不了 analyze。
            // 分隔符与「每文件一段」的格式保持不变。详见 decompiler::dart_preamble_for。
            let (pre, bodies) = merge_rendered(files, true);
            let mut body = String::with_capacity(pre.len() + bodies.len());
            body.push_str(&pre);
            body.push_str(&bodies);
            print!("{body}");
        }
        Some(p) if p.ends_with(".dart") => {
            // 同上：合并成一份合法 Dart（单份前导）
            let (pre, bodies) = merge_rendered(files, false);
            let mut body = String::with_capacity(pre.len() + bodies.len());
            body.push_str(&pre);
            body.push_str(&bodies);
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
            for (name, text) in files {
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
}

/// `dae decompile <bin> [-o DIR|FILE.dart|-]`：只反编译，不写其它产物。
///
/// 与 `export --decompile` 的差别是**只出 dart/**：不写 ida_script/r2_script/asm/text/。
/// 与 `getlib` 的差别是默认范围为全部（可用 --lib/--no-sdk/--app 收窄）。
/// 无 `-o` 时走 stdout——这是「把整个应用的伪代码灌进管道」的唯一入口，
/// 全量导出必须给 out_dir。
#[cfg(feature = "asm")]
fn cmd_decompile(o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
    let bin = o.bin("decompile", lang)?;
    with_analyzer(bin, o.sdk.as_deref(), o.platform.as_deref(), s, true, |a, _, _| {
        let sel = resolve_selection(a, &o);
        let all = a.build_functions(true);
        let picked = filter_libs(&all, &sel);
        let (nl, nc, nf) = counts(&picked);
        if nf == 0 {
            return Err(no_match("decompile", &sel, &all, lang));
        }
        if !sel.is_empty() {
            eprintln!(
                "{}",
                tr(
                    lang,
                    &format!("dae：范围 {nl} 个库 / {nc} 个类 / {nf} 个函数"),
                    &format!("dae: scope is {nl} libs / {nc} classes / {nf} functions")
                )
            );
        }
        let (files, st) = crate::decompiler::render(a, &picked)?;
        emit_decompiled(&o, &files, &st, (nl, nc, nf), lang)
    })
}

#[cfg(not(feature = "asm"))]
fn cmd_decompile(o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
    let _ = (o, s);
    Err(tr(
        lang,
        "decompile：本构建未启用反编译器（capstone）",
        "decompile: this build has no decompiler (capstone)",
    ))
}

// 无 capstone 的构建（--no-default-features）：只读查询仍然可用，涉及反汇编的三个
// 命令明确报「本构建不含反汇编」，而不是给出错误结果。
#[cfg(not(feature = "asm"))]
fn cmd_callers(o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
    let _ = (o, s);
    Err(tr(lang, "callers：本构建未启用反汇编（capstone）", "callers: this build has no disassembler (capstone)"))
}

#[cfg(not(feature = "asm"))]
fn cmd_disasm(o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
    let _ = (o, s);
    Err(tr(lang, "disasm：本构建未启用反汇编（capstone）", "disasm: this build has no disassembler (capstone)"))
}

#[cfg(not(feature = "asm"))]
fn cmd_get(cmd: &str, o: Opts, lang: Lang, s: &Messages) -> Result<(), String> {
    let _ = (o, s);
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
            t("info —— 快照、SDK 与规模概况（不写任何产物）", "info -- snapshot, SDK and size summary (writes no artifact)"),
            t(
                "输出 TSV：容器 / 架构 / SDK / 状态 / 快照形态 / 指令段基址 / 指令表条目 /\n库 / 类 / 函数 / 字符串 / 对象数 / 告警数。",
                "TSV out: container / arch / SDK / status / snapshot form / instructions base /\ninstructions table entries / libraries / classes / functions / strings / objects / warnings."
            )
        ),
        "libs" => format!(
            "{}\n\n  dae libs <binary> [pattern] [-n N] [-o FILE]\n\n{}\n{}\n{}",
            t("libs —— 库（包）清单", "libs -- library (package) listing"),
            t("列（制表符分隔）：lib 名, 类数, 函数数, 原始 URL（按函数数降序）", "tab-separated columns: lib, classes, functions, source URL (sorted by function count)"),
            t("pattern 是子串匹配（库名与 URL 都试）；库名三种写法等价，见下。", "pattern is a substring match over both the lib name and its URL."),
            t("库名前缀即「按包」：--lib testing_app 选中 testing_app/*。", "A lib prefix means \"whole package\": --lib testing_app selects testing_app/*.")
        ),
        "classes" => format!(
            "{}\n\n  dae classes <binary> [pattern] [--lib P] [-n N] [-o FILE]\n\n{}\n{}",
            t("classes —— 类清单（只含有函数的类）", "classes -- class listing (only classes that own at least one function)"),
            t("列（制表符分隔）：cid, lib, 类名, 函数数", "tab-separated columns: cid, lib, class, functions"),
            t(
                "pattern 子串匹配；--lib 限定库。\n\
                 口径：本命令走 build_functions，所以只列至少有一个函数的类；\n\
                 `text/classes.txt` 列的是全部 Class 记录，两者能差很多（实测 animations\n\
                 2177 vs 3358——差的那些类方法全被内联/树摇，只剩记录）。要全量看 classes.txt。",
                "pattern is a substring match; --lib narrows to a library.\n\
                 Scope: this command goes through build_functions, so it lists only classes that\n\
                 own at least one function; `text/classes.txt` lists every Class record. The two\n\
                 can differ substantially (measured on animations: 2177 vs 3358 -- the rest had their\n\
                 methods inlined/tree-shaken). Use classes.txt for the complete inventory."
            )
        ),
        "functions" => format!(
            "{}\n\n  dae functions <binary> [pattern] [--lib P] [--class P] [-n N] [-o FILE]\n\n{}\n{}",
            t("functions —— 函数清单", "functions -- function listing"),
            t("列（制表符分隔）：入口地址, 字节数, lib, 类, 方法名", "tab-separated columns: entry, bytes, lib, class, member"),
            t("pattern 可与方法名、Class.method 或类名匹配。", "pattern matches the member, Class.method or the class name.")
        ),
        "fields" => format!(
            "{}\n\n  dae fields <binary> [pattern] [-n N] [-o FILE]\n\n{}\n{}",
            t("fields —— AOT 快照里保留下来的具名字段", "fields -- named fields the AOT snapshot keeps"),
            t("列（制表符分隔）：类, 字段, 来源(rec/accessor), 字节偏移。", "tab-separated columns: class, field, source (rec/accessor), byte offset"),
            t("AOT 会丢掉绝大多数字段名（Precompiler::DropFields 只在非 PRODUCT 构建保留）。\n只列两条可证路径的结果：快照里的 Field 簇（rec）与隐式访问器名推断（accessor），不猜。", "AOT drops most field names (Precompiler::DropFields keeps them only in non-PRODUCT builds).\nLists only the two provable routes: the snapshot's own Field cluster (rec) and implicit-accessor names (accessor). No name is inferred.")
        ),
        "strings" => format!(
            "{}\n\n  dae strings <binary> [-f TEXT] [-n N] [-o FILE]\n\n{}",
            t("strings —— 快照字符串表检索（大小写不敏感子串）", "strings -- snapshot string table search (case-insensitive substring)"),
            t("列（制表符分隔）：对象 ref, 文本。默认最多列 200 条，-n 调整。", "tab-separated columns: object ref, text. Lists at most 200 by default; -n changes it.")
        ),
        "largest" => format!(
            "{}\n\n  dae largest <binary> [-n N] [--lib P] [-o FILE]\n\n{}",
            t("largest —— 按代码字节数排前 N（默认 20）个函数", "largest -- top-N functions by code size (default 20)"),
            t("列（制表符分隔）：字节数, 入口, lib/类.方法。", "tab-separated columns: bytes, entry, lib/Class.member.")
        ),
        "callers" => format!(
            "{}\n\n  dae callers <binary> <NAME|0xADDR> [--fuzzy] [-o FILE]\n\n{}\n{}",
            t("callers —— 谁调用了它（基于直接调用的静态边）", "callers -- who calls it (static direct-call edges)"),
            t("NAME 可写 lib/类.方法、类.方法或裸方法名；也可给 0x 地址。", "NAME may be lib/Class.member, Class.member, a bare member, or a 0x address."),
            t("间接调用（blr/call reg）目标运行时才定，按设计不解析，只在末尾报数量。", "Indirect calls (blr / call reg) resolve only at runtime and are not guessed; the count is reported.")
        ),
        "disasm" => format!(
            "{}\n\n  dae disasm <binary> <CLASS[.method] | 0xADDR> [-o FILE]\n\n{}\n{}\n{}",
            t("disasm —— 单个函数、一个类，或一个地址的原始反汇编", "disasm -- raw disassembly of one function, a whole class, or an address"),
            t(
                "`0x…` 形式按地址反汇编，接受三种地址：函数入口、stub 表条目、以及表条目内部的子 stub（写屏障族：一个 640 字节表项实际上是 20 个 32 字节变体，调用方直接 bl 到内部地址，所以两个表都查不到）。这是查看未命名 stub 的唯一途径：这些表项没有被任何 Function 对象引用、不在函数表里，按名字的路径结构上够不到它们。窗口长度只从可证的地方取——函数表/stub 表给的长度，或形状校验要求的恰好 8 条指令 = 32 字节；三者都不匹配时报错，不推测窗口长度（推测长度会反汇编到无关字节上，且输出表面上完全正常）。",
                "A positional `0x...` disassembles by address and accepts three kinds: a function entry, a stub-table entry, or a sub-stub inside one (the write-barrier family: one 640-byte table entry is really 20 32-byte variants, and callers bl straight to the inner addresses, so neither table lists them). This is the only way to look at an unnamed stub: these entries are referenced by no Function object and never appear in the function table, so the name-based path structurally cannot reach them. The window length comes only from somewhere provable -- the function/stub table's own length, or the exactly-8-instructions = 32 bytes that the shape check requires; an address none of the three accepts errors instead of guessing a window (a guessed length disassembles unrelated bytes and still looks plausible)."
            ),
            t("arm64 带 blutter 同形的 IL 分组注释（与 asm/ 产物一致）；x64 为纯反汇编。", "arm64 includes the blutter-shaped IL group comments (same as the asm/ artifact); x64 is plain disassembly."),
            t("寄存器已按框架名替换（PP/THR/SP/FP…）。", "Registers are already renamed to framework roles (PP/THR/SP/FP...).")
        ),
        "getclass" | "getmethod" | "getlib" => {
            let (what, what_en) = match cmd {
                "getclass" => ("反编译单个类（含其方法）", "decompile a single class (with its methods)"),
                "getmethod" => ("反编译单个方法", "decompile a single method"),
                _ => ("反编译单个库（包）", "decompile a single library (package)"),
            };
            format!(
                "{}\n\n  dae {cmd} <binary> <NAME> [-o FILE.dart|-o DIR|-]\n\n{}\n{}\n{}",
                t(&format!("{cmd} —— {what}"), &format!("{cmd} -- {what_en}")),
                t("无 -o（或 -o -）→ 伪代码写 stdout，不掺统计，方便管道。", "No -o (or -o -) -> pseudocode to stdout, no stats mixed in, pipe-friendly."),
                t("-o 以 .dart 结尾 → 合并成单个文件；否则当成目录根，写出同形的 <DIR>/dart/<库>.dart。", "-o ending in .dart -> one merged file; otherwise treated as a directory root, writing <DIR>/dart/<lib>.dart."),
                t("没命中会给「是不是想找」提示（放宽为子串匹配）。", "On a miss, dae suggests near matches (relaxed to substring matching).")
            )
        }
        "decompile" => format!(
            "{}\n\n  dae decompile <binary> [-o DIR|FILE.dart|-] [--lib P] [--class P] [--func P]\n                [--exclude-lib P] [--no-sdk] [--app] [--fuzzy]\n\n{}\n{}\n{}\n{}\n{}",
            t("decompile —— 只反编译，不写其它产物", "decompile -- decompile only, writing no other artifact"),
            t(
                "输出路由与 getclass/getmethod/getlib 同一份代码：无 -o 或 -o - 走 stdout\n（每库一段 `// ===== name =====`）；-o FILE.dart 合并成单文件；-o DIR 写\n<DIR>/dart/<库>.dart，与全量导出同形。实测 `getlib X -o D` 与 `decompile --lib X -o D`\n产物逐字节相同。",
                "Output routing is the same code as getclass/getmethod/getlib: no -o (or -o -) goes\nto stdout (one `// ===== name =====` block per library); -o FILE.dart merges into one\nfile; -o DIR writes <DIR>/dart/<lib>.dart, same shape as a full export. Verified that\n`getlib X -o D` and `decompile --lib X -o D` produce byte-identical trees.",
            ),
            t(
                "与 `export --decompile` 的差别是只出 dart/：不写 ida_script / r2_script / asm / text。\n与 getlib 的差别是默认范围为全部。",
                "Unlike `export --decompile` it writes only dart/ -- no ida_script / r2_script /\nasm / text. Unlike getlib, its default scope is all libraries.",
            ),
            t(
                "范围收窄：--lib P（库名前缀=整个包）、--no-sdk（排除 URL 以 dart: 开头的库）、\n--app（再排除 package:flutter）。后两个按库的原始 URL 前缀判定，不是按 mangled\n名猜——library_name 把 dart:core 写成 dart_core，一个叫 dart_core_extra 的包会长得很像。\n实测 Flutter 应用：505 库/15796 函数 → --no-sdk 489/11016 → --app 56/765。",
                "Scope: --lib P (a lib prefix = whole package), --no-sdk (drop libraries whose URL\nstarts with dart:), --app (also drop package:flutter). The last two are decided by the\nlibrary's original URL prefix, not by guessing from the mangled name -- library_name\nwrites dart:core as dart_core, and a package called dart_core_extra would look similar.\nMeasured on a Flutter app: 505 libs/15796 functions -> --no-sdk 489/11016 -> --app 56/765.",
            ),
            t(
                "并行与合并输出：各库并发渲染（默认 n_threads()，即核数、上限 8），\n`DAE_DEC_THREADS=N` 可覆盖——任何设置下产物逐字节一致，因为文件名与「每个入口地址\n归哪个库发射」都由一趟顺序预扫描先定死。合并输出（stdout 与 -o FILE.dart）只发\n一份前导声明：一个目标命中多个库时（混淆过的短类名很常见），逐库拼前导会让\nmem/memSet 等占位函数重复定义，产物直接过不了 dart analyze。",
                "Parallelism and merged output: libraries are rendered concurrently (default\nn_threads(), i.e. core count capped at 8); override with `DAE_DEC_THREADS=N`. Output is\nbyte-identical at any setting, because file names and \"which library emits each entry\npoint\" are settled by a sequential pre-pass first. Merged output (stdout and -o FILE.dart)\nemits exactly one preamble: when a target matches several libraries (common with short\nobfuscated class names), concatenating per-library preambles redefines the mem/memSet\nplaceholders and the result fails dart analyze.",
            ),
            t(
                "不做 ddc 的 `pkg --app`（从 manifest 取应用包名）：Dart 快照没有 manifest，\n猜包名就是编造。要更窄用 --lib <你的包> 或 --exclude-lib <不想要的包>。",
                "There is no ddc-style `pkg --app` (which takes the package from the manifest): a Dart\nsnapshot has no manifest, so guessing the package name would be fabrication. Narrow\nfurther with --lib <your package> or --exclude-lib <unwanted package>.",
            )
        ),
        "export" => format!(
            "{}\n\n  dae export <binary> <out_dir> [--decompile] [--lib P] [--class P] [--func P] [--fuzzy]\n\n{}\n{}\n{}",
            t("export —— 全量（或按筛选）导出所有产物到 out_dir", "export -- write every artifact under out_dir (full or filtered)"),
            t(
                "与快捷形 `dae <binary> <out_dir> …` 完全等价：第一个参数不是已知子命令时，\n会自动补成 export。两种写法产出的产物树逐字节相同（有对拍验证）。",
                "Exactly equivalent to the shortcut `dae <binary> <out_dir> …`: when the first\nargument is not a known subcommand, `export` is prepended. Both forms produce a\nbyte-identical output tree (verified by diff).",
            ),
            t(
                "筛选只作用于函数维度的产物（functions.txt / asm/ / dart/ / call_edges.txt /\ncallgraph.dot）；对象层 dump（pp / objs / strings / libs / classes / arrays / maps）\n始终完整——它们是清单类索引，筛选会使其失去意义。",
                "Filters apply only to function-scoped artifacts (functions.txt / asm/ / dart/ /\ncall_edges.txt / callgraph.dot); the object-layer dumps (pp / objs / strings / libs /\nclasses / arrays / maps) stay complete -- they are the index you pick from.",
            ),
            t(
                "注意：全量模式的摘要走 stdout（人读通道，门禁要解析它），与子命令\n「stdout 只放数据」的口径相反；告警与错误两种模式都走 stderr。",
                "Note: in full-export mode the summary goes to stdout (the human channel, which\nthe gates parse) -- the opposite of subcommands, where stdout carries data only.\nWarnings and errors go to stderr in both modes.",
            )
        ),
        "pp" => format!(
            "{}\n\n  dae pp <binary> [pattern] [-n N] [-o FILE]\n\n{}\n{}\n{}",
            t("pp —— 对象池条目查询", "pp -- object pool entries"),
            t("列（制表符分隔）：偏移, 种类(obj|imm|stub), 值（默认 200 行，-n 调）", "tab-separated columns: offset, kind (obj|imm|stub), value (default 200 rows)"),
            t(
                "值文本与 text/pp.txt 同一份代码（ppobjs::pp_describe），所以两边必然一致。\n种类是槽位类型，值是能描述出的内容——`obj` 而行值是 `Stub` 表示「对象槽，但描述不出来」。",
                "The value text comes from the same function as text/pp.txt (ppobjs::pp_describe),\nso the two cannot disagree. `kind` is the slot type while the value is what could be\ndescribed -- an `obj` row whose value reads `Stub` means \"object slot, not describable\".",
            ),
            t(
                "这些偏移就是反编译产物里 `x0 = \"Hello\" /* pp+0x17f8 */` 的落点，\n也是 `dae findrefs` 的检索面。",
                "These offsets are what the `/* pp+0x17f8 */` annotations in dart/ point at, and\nwhat `dae findrefs` searches.",
            )
        ),
        "objs" => format!(
            "{}\n\n  dae objs <binary> [pattern] [-n N] [-o FILE]\n\n{}\n{}",
            t("objs —— 用户类实例（含字段值）", "objs -- user class instances with field values"),
            t(
                "输出是块不是 TSV：与 text/objs.txt 同形（instance_block 是多行递归 dump），\n压成一行会失去可读性。判据也与产物同一个：只有真解出实例块的（Obj! 开头）才算。",
                "Output is blocks, not TSV: same shape as text/objs.txt (instance_block is a\nmulti-line recursive dump); squeezing it onto one line would make it unreadable.\nThe acceptance rule is the shared one too: only real instance blocks (starting\nwith `Obj!`) count.",
            ),
            t(
                "⚠️ 块里按祖先分组的那部分不可信：它依赖 parent_of 的父类链，而那条链目前没有\n真值支撑（实测 App 的父类被解成 SceneBuilder 而非 StatefulWidget）。字段值本身可读，\n继承层级别当结论。详见 src/analyzer.rs 里 sid 处的注释。",
                "⚠️ The ancestor grouping inside a block is not trustworthy: it relies on the\nparent_of chain, which currently has no ground-truth support (measured: App\'s super\nresolves to SceneBuilder instead of StatefulWidget). The field values themselves are\nreadable; do not treat the inheritance grouping as a conclusion. See the comment at\nthe `sid` site in src/analyzer.rs.",
            )
        ),
        "stubs" => format!(
            "{}\n\n  dae stubs <binary> [pattern] [-n N] [-o FILE]\n\n{}\n{}\n{}",
            t(
                "stubs —— 指令表里没有被任何 Function 引用的条目",
                "stubs -- instruction-table entries not referenced by any Function",
            ),
            t("列（制表符分隔）：入口, 字节数, 名字（解不出就留空）", "tab-separated columns: entry, bytes, name (empty when unresolved)"),
            t(
                "functions.txt 只列「有 Function 对象引用」的表项，其余的在这里。\n⚠️ 它们不全是 stub，也不构成表的前缀：Reqable（first_entry_with_code=48455）里\n有 24932 条（53.4%、8.09 MB）以标准 Dart EnterFrame 序言开头、长度最长 27708 字节，\n是没有名字的函数体；同时 7798 条的下标 ≥ first_entry 而 9530 个已命名函数的下标 < 它。\nfirst_entry_with_code==0 的语料（material_3_demo/微博/ChatGLM）里这一比例只有 0.4–1.2%。",
                "functions.txt lists only the entries a Function object references; this is the rest.\nThey are not all stubs and do not form a prefix of the table: on Reqable\n(first_entry_with_code=48455) 24932 of them (53.4%, 8.09 MB) start with a standard Dart\nEnterFrame prologue and run up to 27708 bytes -- they are unnamed function bodies --\nwhile 7798 sit at index >= first_entry and 9530 named functions sit below it. On corpora\nwith first_entry_with_code==0 (material_3_demo/Weibo/ChatGLM) that share is only 0.4-1.2%.",
            ),
            t(
                "名字解不出就是空——绝不为凑覆盖率编名字（门禁 alloc_stub_naming 盯着）。",
                "An unresolved name stays empty -- names are never invented to pad coverage\n(the alloc_stub_naming gate enforces this).",
            )
        ),
        "members" => format!(
            "{}\n\n  dae members <binary> [NAME] [--class X] [--method|--field] [-n N] [-o FILE]\n\n{}\n{}\n{}",
            t("members —— 方法与字段的统一名字检索", "members -- unified method/field name search"),
            t(
                "列（制表符分隔）：kind(method|field), class, member, detail；\ndetail 对方法是入口地址，对字段是 `来源:偏移`（rec=快照里写着，accessor=访问器名推断）。",
                "tab-separated columns: kind (method|field), class, member, detail; detail is the entry\naddress for a method and `source:offset` for a field (rec = written in the snapshot,\naccessor = inferred from an implicit accessor name).",
            ),
            t("NAME 是子串匹配，同时试成员名与类名；--class 按类名收窄；--method/--field 二选一。", "NAME is a substring match tried against both the member and the class name; --class narrows by class; --method/--field pick one kind."),
            t(
                "一处有意的不对称：--lib 只作用于方法。字段行在快照里没有库归属（Field 簇给的是\n类/名/偏移），与其让 --lib 对字段静默无效，不如明说。",
                "One deliberate asymmetry: --lib applies to methods only. Field rows carry no library\nattribution in the snapshot (the Field cluster gives class/name/offset), so instead of --lib\nsilently having no effect on fields, the restriction is documented here.",
            )
        ),
        "callees" => format!(
            "{}\n\n  dae callees <binary> <NAME|0xADDR> [--fuzzy] [-n N] [-o FILE]\n\n{}\n{}\n{}",
            t("callees —— 它调了谁（callers 的反方向）", "callees -- what it calls (the reverse of callers)"),
            t("列与 callers 完全相同：at, from_ep, from, ->, to_ep, to_name，方便两边对着看。", "Columns are identical to callers: at, from_ep, from, ->, to_ep, to_name, so the two read side by side."),
            t(
                "间接调用（blr x8 / 寄存器 call）的目标运行时才可定，按设计不解析、也不进表，\n只在 stderr 的计数里说明有多少个——列出来就得给个目标，而给不出真的目标。",
                "Indirect call targets (blr x8 / register call) are only known at runtime, so they are\nnot resolved by design and do not appear as rows; the stderr count says how many\nthere are. Listing them would require naming a target, and there is no true target to name.",
            ),
            t(
                "与 callers 一样扫整个程序，所以 --lib/--class/--func 在这里明确报错而不是被\n静默忽略（否则「它调谁」是不完整的答案，而你看不出来）。",
                "Like callers it scans the whole program, so --lib/--class/--func are rejected\nexplicitly rather than silently ignored (otherwise \"what it calls\" would be an\nincomplete answer with no way to tell).",
            )
        ),
        "findrefs" => format!(
            "{}\n\n  dae findrefs <binary> string TEXT\n  dae findrefs <binary> kind NAME\n\n{}\n{}\n{}\n{}",
            t("findrefs —— 哪些代码位置从对象池里加载了它", "findrefs -- which code sites load it from the object pool"),
            t("列（制表符分隔）：at, from_ep, from, pp_offset, value（按地址排序去重）", "tab-separated columns: at, from_ep, from, pp_offset, value (address-sorted, deduped)"),
            t(
                "零编造判据：偏移解析走 decompiler::PoolRefs，与产物里 `/* pp+0x… */` 注释同一份\n代码；门禁 tests/cli_query.rs 另外用两条独立路径复核每个命中——值列与 text/pp.txt\n逐字相同，且 at+偏移能在 `dae disasm` 的原始行里字面看到（实测 679/679）。",
                "Zero-fabrication criterion: offsets resolve through decompiler::PoolRefs, the same\ncode that emits the `/* pp+0x… */` annotations; the tests/cli_query.rs gate\ncross-checks every hit two independent ways -- the value column matches text/pp.txt\nverbatim, and at+offset is literally visible in `dae disasm` output (measured 679/679).",
            ),
            t(
                "只有 `string TEXT`（池里的字符串字面量，子串、大小写不敏感）与 `kind NAME`\n（对象种类整名，即 dart/ 里 /* TypeArguments */ 那个词）两种。",
                "Only `string TEXT` (pool string literals; substring, case-insensitive) and\n`kind NAME` (exact object kind -- the /* TypeArguments */ word in dart/).",
            ),
            t(
                "不提供 field：编译后的机器码里没有符号化的字段引用，只剩裸位移，按位移匹配会把\n大量无关的 [x, #0x18] 报成命中——那是推测而非检索。也不叫 type：池条目描述形是\n`Kind: 内容`，那个前缀是对象类别而非类型名，当类型名搜会既漏又误。",
                "No `field`: compiled code carries no symbolic field reference, only a bare\ndisplacement, so matching on displacement would report unrelated [x, #0x18] as hits --\nthat would be inference rather than lookup. Not called `type` either: a pool entry\'s description is\n`Kind: content`, and that prefix is the object category, not a type name.",
            )
        ),
        "version" => format!(
            "{}\n\n  dae version\n\n{}\n{}",
            t("version —— 打印名字与版本", "version -- print the name and version"),
            t(
                "输出一行 `dae <版本>`。版本取自构建时确定的 GIT_VERSION：CI 发版用 tag，\n本地构建用 `git describe --tags --exact-match`，都不适用时回落到 Cargo.toml 的版本号。",
                "Prints one line, `dae <version>`. The version comes from GIT_VERSION, resolved at\nbuild time: the tag in CI releases, `git describe --tags --exact-match` locally, and\nthe Cargo.toml version when neither applies."
            ),
            t(
                "顶层的 -V 与 --version 等价于本命令。本命令不接受其它参数。",
                "The top-level -V and --version are equivalent to this command. It takes no other argument."
            )
        ),
        "help" => format!(
            "{}\n\n  dae help\n  dae help <command>\n\n{}\n{}\n{}",
            t("help —— 打印使用说明", "help -- print the usage guide"),
            t(
                "不带参数时打印完整指南：用法、参数、全部子命令（按用途分组）、选项、输出、\n命名口径、退出码与示例。带命令名时只打印那一条命令的说明。",
                "Without an argument, prints the full guide: usage, arguments, every command grouped by\npurpose, options, output, naming rules, exit status and examples. With a command name,\nprints only that command's help."
            ),
            t(
                "以下四种形态输出完全相同：dae、dae -h、dae --help、dae help。\n每条命令也都接受 -h 与 --help，且与 `dae help <命令>` 输出相同。",
                "These four invocations produce identical output: dae, dae -h, dae --help, dae help.\nEvery command also accepts -h and --help, with the same output as `dae help <command>`."
            ),
            t(
                "命令名不存在时按用法错误处理（退出码 2）并列出有效命令名，\n而不是退回打印整份指南——那会把拼写错误藏起来。",
                "An unknown command name is a usage error (exit status 2) and lists the valid names,\nrather than falling back to the whole guide, which would hide a typo."
            )
        ),
        _ => help(lang),
    }
}

pub fn help(lang: Lang) -> String {
    let zh = matches!(lang, Lang::Zh);
    let t = |z: &str, e: &str| if zh { z.to_string() } else { e.to_string() };
    let mut h = String::new();

    // 每条命令一行：`dae <cmd> <args>` 左对齐到 40 列，后接一句说明。
    // 用一个闭包而不是 30 段 writeln!，是为了让「对齐宽度」只有一处——手写 30 遍必然对不齐。
    let row = |h: &mut String, cmd: &str, desc: String| {
        // 40 列按最长的一条定（`decompile <binary> [-o DIR|FILE.dart|-]`，39 字符）。
        let _ = writeln!(h, "    dae {cmd:<40}{}", desc);
    };
    let group = |h: &mut String, name: String| {
        let _ = writeln!(h, "  {name}");
    };

    // ---- 头部 ----
    // 两行而不是一行：合成一行时英文有 117 列，超过终端宽度就会被折行、把对齐全毁掉。
    let _ = writeln!(
        h,
        "{}",
        t(
            &format!("dae {} — Dart AOT 快照调试信息静态导出工具", env!("GIT_VERSION")),
            &format!("dae {} -- static exporter of Dart AOT snapshot debug information", env!("GIT_VERSION"))
        )
    );
    let _ = writeln!(
        h,
        "{}",
        t(
            "支持 Dart 2.7–3.14β；容器 Mach-O / ELF / PE；架构 x64 / arm64。",
            "Supports Dart 2.7-3.14b; containers Mach-O, ELF and PE; architectures x64 and arm64."
        )
    );
    let _ = writeln!(h, "https://github.com/ejfkdev/dae");
    let _ = writeln!(h);

    // 用法行两种语言都用 ASCII：SYNOPSIS 按 man-page 惯例不翻译，只翻译行尾说明。
    // 否则 `[选项]` 这类全角字符会让 `{:<N}` 的按字符补宽在终端里对不齐（CJK 是双宽）。
    let usage = |h: &mut String, form: &str, zh_desc: &str, en_desc: &str| {
        let _ = writeln!(h, "  {form:<40}{}", t(zh_desc, en_desc));
    };

    // ---- 用法 ----
    let _ = writeln!(h, "{}", t("用法", "USAGE"));
    usage(&mut h, "dae <binary> <out_dir> [options]",
        "导出全部产物（快捷形）", "export all artifacts (shortcut form)");
    usage(&mut h, "dae export <binary> <out_dir> [options]",
        "导出全部产物（显式形，与上等价）", "export all artifacts (explicit form; equivalent)");
    usage(&mut h, "dae <command> <binary> [arguments]",
        "执行单条查询或反编译命令", "run one query or decompilation command");
    usage(&mut h, "dae help [command]",
        "打印本说明，或某一条命令的说明", "print this text, or the help of one command");
    usage(&mut h, "dae version", "打印版本", "print the version");
    let _ = writeln!(h);
    let _ = writeln!(
        h,
        "  {}",
        t(
            "不带参数运行 dae 时打印本说明。每条命令都接受 -h 与 --help。",
            "Running dae with no argument prints this text. Every command accepts -h and --help."
        )
    );
    let _ = writeln!(h);

    // ---- 参数 ----
    // 续行缩进 13 列：2 列前导 + `<binary>` 8 字符 + 3 列间隔，与上一行的说明起点对齐。
    let _ = writeln!(h, "{}", t("参数", "ARGUMENTS"));
    let _ = writeln!(
        h,
        "  <binary>   {}",
        t(
            "目标文件：含 Dart AOT 快照的 Mach-O、ELF 或 PE。",
            "Target file: Mach-O, ELF or PE containing a Dart AOT snapshot."
        )
    );
    let _ = writeln!(
        h,
        "             {}",
        t(
            "也接受 .app 与 .framework 目录，会自动定位其中的二进制。",
            "A .app or .framework directory is accepted; the binary inside it is located."
        )
    );
    let _ = writeln!(
        h,
        "  <out_dir>  {}",
        t("输出目录；不存在则创建。", "Output directory. Created if absent.")
    );
    let _ = writeln!(h);

 

    // ---- 命令 ----
    let _ = writeln!(h, "{}", t("命令", "COMMANDS"));
    group(&mut h, t("概览", "Overview"));
    row(&mut h, "info      <binary>", t("快照、SDK 与规模概况", "snapshot, SDK and size summary"));
    row(&mut h, "libs      <binary> [pattern]", t("库（包）清单，含类数与函数数", "libraries with class and function counts"));
    row(&mut h, "classes   <binary> [pattern] [--lib P]", t("类清单（只列至少拥有一个函数的类）", "classes that own at least one function"));
    row(&mut h, "functions <binary> [pattern] [--lib P]", t("函数清单：入口地址、字节数、归属", "functions: entry address, size, owner"));
    row(&mut h, "largest   <binary> [-n N]", t("按字节数排序的前 N 个函数", "the N largest functions by size"));
    let _ = writeln!(h);

    group(&mut h, t("检索", "Search"));
    row(&mut h, "strings   <binary> [-f TEXT]", t("字符串表检索", "search the string table"));
    row(&mut h, "fields    <binary> [pattern]", t("恢复出的字段名，含来源与字节偏移", "recovered field names with source and byte offset"));
    row(&mut h, "members   <binary> [NAME] [--class X]", t("方法与字段的名字检索", "method and field name search"));
    row(&mut h, "findrefs  <binary> string TEXT", t("从对象池加载该字面量的代码位置", "code sites loading this literal from the object pool"));
    row(&mut h, "findrefs  <binary> kind NAME", t("从对象池加载该种类对象的代码位置", "code sites that load an object of this kind"));
    row(&mut h, "callers   <binary> <NAME|0xADDR>", t("调用给定函数的位置", "callers of a function"));
    row(&mut h, "callees   <binary> <NAME|0xADDR>", t("给定函数调用的目标（列同 callers）", "callees of a function; same columns as callers"));
    let _ = writeln!(h);

    group(&mut h, t("对象层（text/ 产物的查询入口，数据同源）", "Object layer (query interface to the text/ artifacts; same data)"));
    row(&mut h, "pp        <binary> [pattern]", t("对象池条目", "object pool entries"));
    row(&mut h, "objs      <binary> [pattern]", t("用户类实例，含字段值", "instances of user classes, with field values"));
    row(&mut h, "stubs     <binary> [pattern]", t("没有被任何 Function 引用的指令表条目", "table entries no Function object references"));
    let _ = writeln!(h);

    group(&mut h, t("反编译", "Decompilation"));
    row(&mut h, "getclass  <binary> <CLASS>", t("反编译单个类", "decompile a single class"));
    row(&mut h, "getmethod <binary> <CLASS.method>", t("反编译单个方法", "decompile a single method"));
    row(&mut h, "getlib    <binary> <LIB>", t("反编译单个库；前缀选中整个包", "decompile one library; a prefix selects the package"));
    row(&mut h, "decompile <binary> [-o DIR|FILE.dart|-]", t("只反编译，不写其它产物；默认全部库", "decompile only; no other artifacts; all libraries"));
    let _ = writeln!(h);

    group(&mut h, t("底层", "Low-level"));
    row(&mut h, "disasm    <binary> <NAME|0xADDR>", t("单个函数或表项的反汇编（arm64）", "disassembly of a function or table entry (arm64)"));
    let _ = writeln!(h);

    group(&mut h, t("导出", "Export"));
    row(&mut h, "export    <binary> <out_dir> [options]", t("把全部产物写进 out_dir", "write every artifact under out_dir"));
    let _ = writeln!(
        h,
        "    {}",
        t(
            "第一个参数不是子命令时自动补 export，故快捷形与显式形完全等价。",
            "export is prepended when the first argument is not a command, so the two forms are equivalent."
        )
    );
    let _ = writeln!(h);

    group(&mut h, t("其它", "Meta"));
    row(&mut h, "help      [command]", t("本说明；带命令名时给该命令的说明", "this text; with a command name, that command's help"));
    row(&mut h, "version", t("打印名字与版本", "print the name and version"));
    let _ = writeln!(h);

    // ---- 选项 ----
    let _ = writeln!(h, "{}", t("选项", "OPTIONS"));
    let _ = writeln!(
        h,
        "  {}",
        t(
            "除 --decompile 只对导出命令有效外，下列选项对所有命令有效。",
            "All options apply to every command except --decompile, which is export-only."
        )
    );
    let opt = |h: &mut String, flag: &str, zh_desc: &str, en_desc: &str| {
        let _ = writeln!(h, "  {flag:<26}{}", t(zh_desc, en_desc));
    };
    opt(&mut h, "--sdk-profile PATH",
        "指定 SDK Profile（默认：内嵌 26 版，按快照版本指纹识别）",
        "SDK profile to use (default: 26 embedded, detected by fingerprint)");
    opt(&mut h, "--platform-profile PATH",
        "指定平台 Profile（默认：按容器与架构选择）",
        "platform profile to use (default: by container and architecture)");
    opt(&mut h, "--decompile",
        "额外产出 dart/ 伪 Dart（实验性；已结构化 if/else 与循环）",
        "also emit dart/ pseudocode (experimental; structured if/else and loops)");
    opt(&mut h, "--lib PATTERN",
        "只保留这些库（可重复；库名前缀即整个包）",
        "restrict to these libraries (repeatable; prefix = whole package)");
    opt(&mut h, "--class PATTERN",
        "只保留这些类（可重复）",
        "restrict to these classes (repeatable)");
    opt(&mut h, "--func PATTERN",
        "只保留这些函数（可重复；接受 Class.method）",
        "restrict to these functions (repeatable; Class.method is accepted)");
    opt(&mut h, "--fuzzy",
        "上面三个模式串按子串匹配（默认精确）",
        "treat the three patterns above as substrings (default: exact)");
    opt(&mut h, "--exclude-lib PATTERN",
        "排除这些库（可重复；前缀规则与 --lib 相同）",
        "exclude these libraries (repeatable; same prefix rule as --lib)");
    opt(&mut h, "--no-sdk",
        "排除 SDK 库（URL 以 dart: 开头者）",
        "exclude SDK libraries (those whose URL begins with dart:)");
    opt(&mut h, "--app",
        "只保留应用侧代码（再排除 package:flutter）；与 --no-sdk 互斥",
        "keep app-side code only (excludes package:flutter; not with --no-sdk)");
    opt(&mut h, "-o, --output PATH",
        "写入 PATH 而非 stdout；-o - 等价于 stdout",
        "write to PATH instead of stdout; -o - is equivalent to stdout");
    opt(&mut h, "-n, --limit N", "最多打印 N 行", "print at most N rows");
    opt(&mut h, "-f, --find TEXT", "检索文本（strings 使用）", "filter text (used by strings)");
    opt(&mut h, "-h, --help", "打印该命令的说明", "print the help of this command");
    opt(&mut h, "-V, --version",
        "打印版本（仅顶层；另见 dae version）",
        "print the version (top level only; see also dae version)");
    let _ = writeln!(h);

    // ---- 输出 ----
    let _ = writeln!(h, "{}", t("输出", "OUTPUT"));
    let _ = writeln!(
        h,
        "  {}",
        t("导出命令写入 <out_dir> 的内容：", "Written under <out_dir> by the export commands:")
    );
    let out_row = |h: &mut String, name: &str, desc: String| {
        let _ = writeln!(h, "    {name:<15}{desc}");
    };
    out_row(&mut h, "ida_script/", t(
        "IDA 命名脚本与结构头（addNames.py、ida_dart_struct.h）",
        "IDA naming script and struct header (addNames.py, ida_dart_struct.h)"));
    out_row(&mut h, "r2_script/", t(
        "radare2 命名脚本与结构头（addNames.r2、r2_dart_struct.h）",
        "radare2 naming script and struct header (addNames.r2, r2_dart_struct.h)"));
    out_row(&mut h, "frida.js", t(
        "Frida 运行时模板，含 Classes 数组",
        "Frida runtime template with the Classes array"));
    out_row(&mut h, "asm/", t(
        "capstone 反汇编与 IL 注释（仅 arm64）",
        "capstone disassembly with IL comments (arm64 only)"));
    out_row(&mut h, "text/", t(
        "制表符分隔的各类清单：pp、objs、strings、libs、classes、functions、",
        "tab-separated dumps: pp, objs, strings, libs, classes, functions,"));
    let _ = writeln!(h, "    {:<15}{}", "", t(
        "arrays、maps、fields、stubs、call_edges",
        "arrays, maps, fields, stubs, call_edges"));
    out_row(&mut h, "callgraph.dot", t(
        "已命名函数之间的直接调用图（Graphviz）",
        "direct call graph between named functions (Graphviz)"));
    out_row(&mut h, "dart/", t(
        "逐函数伪 Dart；需要 --decompile",
        "per-function pseudocode; requires --decompile"));
    let _ = writeln!(h);

    // ---- 命名口径 ----
    // 逐行 writeln! 而不是一个多行字符串：Rust 的 `\` 续行会吃掉下一行的前导空格，
    // 于是要靠占位符再 replace 回来——那正是容易写错的地方（本版曾因此截断过文件）。
    let _ = writeln!(h, "{}", t("命名口径", "NAMING"));
    let _ = writeln!(h, "  {}", t(
        "名字既接受手写形式，也接受上一条命令输出里的原样形式：",
        "Names are accepted both as written by hand and as printed by the previous command:"));
    for line in [
        t("库名有三种等价写法——functions.txt 的 lib 列（testing_app$screens$home）、",
          "A library has three equivalent forms: the lib column of functions.txt"),
        t("libs.txt 的 URL（package:testing_app/screens/home.dart）、产物文件名",
          "(testing_app$screens$home), the URL from libs.txt"),
        t("（testing_app_screens_home）。库名按前缀匹配，故 --lib testing_app 与",
          "(package:testing_app/screens/home.dart), and the artifact file name"),
        t("getlib testing_app 都指整个包。",
          "(testing_app_screens_home). Library names match by prefix, so --lib testing_app"),
        t("类名默认精确匹配（大小写不敏感兜底）；加 --fuzzy 才按子串。",
          "and getlib testing_app both denote the whole package."),
        t("函数名接受四种写法：Class.method、lib/Class.method、产物中的下划线形式",
          "Class names match exactly by default, with a case-insensitive fallback;"),
        t("Class_method，以及 callers/callees/findrefs/text/call_edges.txt 输出中的",
          "--fuzzy makes them substrings."),
        t("全点号形式 lib.Class.method。最后一种的存在是为了让上一条命令的输出",
          "Function names accept four forms: Class.method, lib/Class.method, the artifact"),
        t("可以直接作为下一条命令的输入。",
          "underscore form Class_method, and the all-dots form lib.Class.method used by"),
    ] {
        let _ = writeln!(h, "    {line}");
    }
    for line in [
        t("", "callers, callees, findrefs and text/call_edges.txt. The last exists so that the"),
        t("", "output of one command can be fed directly into the next."),
    ] {
        if !line.is_empty() {
            let _ = writeln!(h, "    {line}");
        }
    }
    let _ = writeln!(h);

    // ---- 退出码 ----
    let _ = writeln!(h, "{}", t("退出码", "EXIT STATUS"));
    let _ = writeln!(h, "  {}", t("0  成功。", "0   Success."));
    let _ = writeln!(h, "  {}", t(
        "1  运行期错误，含没有命中与解析漂移。",
        "1   Runtime error, including no match and parse drift."));
    let _ = writeln!(h, "  {}", t("2  用法错误。", "2   Usage error."));
    let _ = writeln!(h);
    let _ = writeln!(h, "  {}", t(
        "查询类命令的 stdout 只承载数据，诊断一律走 stderr，因此可直接接入管道。",
        "For query commands stdout carries data only and every diagnostic goes to stderr, so"));
    let _ = writeln!(h, "  {}", t(
        "导出命令相反：摘要走 stdout，告警走 stderr。",
        "output can be piped directly. The export commands are the opposite: their summary"));
    let _ = writeln!(h, "  {}", t(
        "每条查询命令都会重新解析一次快照（数十毫秒），它省去的是写全量产物。",
        "goes to stdout and warnings to stderr. Each query command re-parses the snapshot"));
    // 这一行只有英文有（中文三行就说完了）；空串时必须整行不写，否则会留下一行
    // 只有两个空格的空白行——终端里看不出来，但 wc -l 与门禁的行数断言都会数到它。
    let tail = t("", "(tens of milliseconds); what it avoids is writing the full export.");
    if !tail.is_empty() {
        let _ = writeln!(h, "  {tail}");
    }
    let _ = writeln!(h);

    // ---- 示例 ----
    let _ = writeln!(h, "{}", t("示例", "EXAMPLES"));
    for ex in [
        "dae App.app out/",
        "dae App.app out/ --decompile --app",
        "dae libs app.so | head",
        "dae getmethod app.so HomePage._increment",
        "dae callers app.so 0x48098c",
        "dae app.so out/ --sdk-profile profiles/sdk/dart-3.3.4-w64-no-compressed.json",
    ] {
        let _ = writeln!(h, "  {ex}");
    }

    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subcommand_detection() {
        assert!(is_subcommand("getclass"));
        assert!(is_subcommand("libs"));
        assert!(is_subcommand("export"));
        assert!(!is_subcommand("app.apk"));
        assert!(!is_subcommand("./info")); // 与本机文件同名时走全量导出
    }

    /// clap 解析 → `Opts` 的转换必须把每个 flag 都带过去。
    ///
    /// 这条测试盯的是「解析了却没生效」这类 bug：参考项目 ddc 的 `callers` 解析了 `--dex`
    /// 又在重建 argv 时丢掉，于是 `--dex 不存在的镜像` 照样返回结果。dae 现在只有一处
    /// 转换（[`opts_of`]），所以要么全部带过去、要么编译不过。
    #[test]
    fn positional_parsing() {
        use clap::Parser;
        let cli = crate::args::Cli::try_parse_from([
            "dae", "classes", "bin.so", "HomePage", "-n", "5", "--lib", "app", "--fuzzy",
        ])
        .unwrap();
        let Cmd::Classes(q) = cli.cmd else { panic!("expected classes") };
        assert_eq!(q.binary.as_deref(), Some("bin.so"));
        assert_eq!(q.pattern.as_deref(), Some("HomePage"));
        let o = opts_of(&q.common, q.binary.unwrap(), q.pattern.into_iter().collect());
        assert_eq!(o.bin.as_deref(), Some("bin.so"));
        assert_eq!(o.rest, vec!["HomePage".to_string()]);
        assert_eq!(o.n, Some(5));
        assert_eq!(o.libs, vec!["app".to_string()]);
        assert!(o.fuzzy);
    }

    /// 位置参数与 flag 的相对顺序无关——手写解析器做不到这点（ddc 的 `info -d x app.apk`
    /// 就是把 `-d` 的取值当成了输入路径）。
    #[test]
    fn flags_may_precede_positionals() {
        use clap::Parser;
        let cli = crate::args::Cli::try_parse_from([
            "dae", "info", "-n", "3", "--lib", "app", "bin.so",
        ])
        .unwrap();
        let Cmd::Info(q) = cli.cmd else { panic!("expected info") };
        assert_eq!(q.binary.as_deref(), Some("bin.so"));
        assert_eq!(q.common.limit, Some(3));
        assert_eq!(q.common.lib, vec!["app".to_string()]);
    }

    /// 取出任意子命令的 help 标记。
    ///
    /// 故意**不用 `_ =>` 兜底**：新增一条命令而忘了给它 help 标记时，这里会编译不过，
    /// 而不是让下面那条测试静默放过它。
    fn help_flag(c: &Cmd) -> bool {
        match c {
            Cmd::Export(a) => a.common.help,
            Cmd::Members(a) => a.common.help,
            Cmd::Findrefs(a) => a.common.help,
            Cmd::Decompile(a) => a.common.help,
            Cmd::Info(a)
            | Cmd::Libs(a)
            | Cmd::Classes(a)
            | Cmd::Functions(a)
            | Cmd::Largest(a)
            | Cmd::Strings(a)
            | Cmd::Fields(a)
            | Cmd::Pp(a)
            | Cmd::Objs(a)
            | Cmd::Stubs(a) => a.common.help,
            Cmd::Callers(a)
            | Cmd::Callees(a)
            | Cmd::Disasm(a)
            | Cmd::Getclass(a)
            | Cmd::Getmethod(a)
            | Cmd::Getlib(a) => a.common.help,
            Cmd::Help(a) => a.help,
            Cmd::Version(a) => a.help,
        }
    }

    /// `-h/--help` 必须在**缺少位置参数**时也能解析成功。
    ///
    /// 这条盯的是一个曾经对**全部 22 条命令**生效的缺陷：clap 的必填位置参数校验发生在
    /// 解析阶段、早于 handler，于是 `dae libs -h` 先撞上「required arguments were not
    /// provided: <BINARY>」而以 2 退出，`-h` 永远没机会执行。而 `dae help libs` 是好的
    /// （它没有必填位置参数），所以只测后者的门禁整整一个版本没发现前者全坏。
    ///
    /// 修法是把位置参数声明成 `Option<String>`、由 handler 校验（见 `src/args.rs` 顶部），
    /// 这条测试就是那个约定的看守：任何一条命令退回必填位置参数、或新增命令时忘了
    /// help 标记，都会在这里失败。
    #[test]
    fn help_flag_parses_without_positionals() {
        use clap::Parser;
        for cmd in SUBCOMMANDS {
            for flag in ["-h", "--help"] {
                let argv = ["dae", cmd, flag];
                let cli = crate::args::Cli::try_parse_from(argv).unwrap_or_else(|e| {
                    panic!("`dae {cmd} {flag}` 解析失败（位置参数又变必填了？）: {e}")
                });
                assert!(
                    help_flag(&cli.cmd),
                    "`dae {cmd} {flag}` 没有把 help 标记解析出来"
                );
            }
        }
        // help 自己也要能吃 -h（它的结构体没有共享选项组，容易漏）
        for argv in [["dae", "help", "-h"], ["dae", "help", "--help"]] {
            let cli = crate::args::Cli::try_parse_from(argv).unwrap();
            assert!(help_flag(&cli.cmd), "{argv:?} 没有把 help 标记解析出来");
        }
    }

    /// 缺少位置参数时必须是**用法错误**：`Opts` 拿不到 binary，handler 无从运行。
    /// 这条钉住「位置参数改成 Option 之后仍然会报错」，否则漏参数会静默变成空结果。
    #[test]
    fn missing_positional_still_parses_but_is_incomplete() {
        use clap::Parser;
        let cli = crate::args::Cli::try_parse_from(["dae", "libs"]).unwrap();
        let Cmd::Libs(q) = cli.cmd else { panic!("expected libs") };
        assert!(q.binary.is_none(), "缺 binary 时应当是 None，由 handler 报用法错误");
    }

    #[test]
    fn unknown_option_is_an_error() {
        use clap::Parser;
        assert!(crate::args::Cli::try_parse_from(["dae", "info", "bin.so", "--nope"]).is_err());
    }

    /// `-o -`（stdout 记号）必须被当成取值而不是 flag——手写解析器为此专门写了
    /// `a != "-"` 的例外，clap 天然如此，这里钉住它别退化。
    #[test]
    fn dash_is_a_value_not_a_flag() {
        use clap::Parser;
        let cli = crate::args::Cli::try_parse_from(["dae", "getclass", "bin.so", "Foo", "-o", "-"])
            .unwrap();
        let Cmd::Getclass(t) = cli.cmd else { panic!("expected getclass") };
        assert_eq!(t.common.output.as_deref(), Some("-"));
    }
}