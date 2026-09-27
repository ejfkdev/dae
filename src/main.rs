//! Dart AOT 快照调试信息导出工具（配置驱动）。
//!
//! 用法:
//!   dae <binary> <out_dir> [--sdk-profile P] [--platform-profile P] [--decompile]
//!   dae <subcommand> <binary> [...]      # 渐进式，见 `dae help`
//!
//! 本文件只负责三件事：选语言、截获 `-h`/`-V`（要出双语文本）、把快捷形式补成
//! `export` 子命令后交给 clap。命令树声明在 `src/args.rs`，实现在 `src/cli.rs`。

use clap::Parser;

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    let lang = dae::locale::detect();
    let s = dae::locale::messages(lang);
    let args: Vec<String> = std::env::args().skip(1).collect();

    // 无参数：打帮助并以 2 退出（用法错误）。文本用本项目双语版而不是 clap 自动生成的。
    if args.is_empty() {
        print_help(&s);
        std::process::exit(2);
    }
    // 帮助与版本先截获：clap 的那份是英文通用 flag 列表，而本项目的帮助写了每个命令的
    // 输出列格式与命名口径，且是双语的。
    match args[0].as_str() {
        "-h" | "--help" => {
            print_help(&s);
            std::process::exit(0);
        }
        "-V" | "--version" => {
            println!("dae {}", env!("GIT_VERSION"));
            std::process::exit(0);
        }
        _ => {}
    }

    // 快捷形式：第一个参数不是已知子命令 ⇒ 当成 `export` 的参数。
    // 于是 `dae App.app out/ --decompile` 与 `dae export App.app out/ --decompile` 完全等价。
    // 本机恰好有个叫 `info` 的文件时写 `./info` 即可落回全量导出（与既有口径一致）。
    //
    // 顺带修掉一个歧义：以前 `dae bogus App.app out/` 会把 `bogus` 当二进制路径去读、
    // 报 "failed to read binary" 并 exit 1；现在 clap 报「unrecognized subcommand」并 exit 2，
    // 即用法错误该有的退出码。（参考项目 ddc 因为把判定放在路径解析之后，至今仍是前一种。）
    //
    // ⚠️ `try_parse_from` 把**第 0 个元素当程序名**，所以这里必须自己补上 "dae"——
    // 少补一个会让 `dae info` 被读成「程序名 info、缺子命令」。
    let mut argv: Vec<String> = Vec::with_capacity(args.len() + 2);
    argv.push("dae".to_string());
    if !dae::cli::is_subcommand(&args[0]) {
        argv.push("export".to_string());
    }
    argv.extend(args);

    let cli = match dae::args::Cli::try_parse_from(&argv) {
        Ok(c) => c,
        Err(e) => {
            // clap 的用法错误文本只有英文（clap 自身无 i18n）。保留它精确的诊断
            // （哪个参数、期望什么、正确的 usage 行），另加一行双语指路，
            // 免得中文用户只看到英文。
            //
            // 退出码 **2 = 用法错误**，与本项目既有口径一致；手写解析器时代
            // `dae info bin --nope` 报的是 1，把用法错误混进了运行期错误。
            eprintln!(
                "{}: {}",
                s.err_prefix,
                lang.pick(
                    "用法错误（`dae help` 列出全部命令与选项）",
                    "usage error (`dae help` lists every command and option)"
                )
            );
            e.exit()
        }
    };
    std::process::exit(dae::cli::run_cmd(cli.cmd, lang, &s));
}

fn print_help(s: &dae::locale::Messages) {
    if s.lang == dae::locale::Lang::Zh {
        // 中文语系
        println!("dae {} — Dart AOT 快照调试信息静态导出工具（支持 Dart 2.7–3.14β；Mach-O/ELF/PE，x64/arm64）", env!("GIT_VERSION"));
        println!("https://github.com/ejfkdev/dae");
        println!();
        println!("用法: dae <binary> <out_dir> [选项]        # 全量或筛选导出");
        println!("      dae <子命令> <binary> [选项]        # 渐进式：先查清单，再定点反编译");
        println!("                                          （dae help 看全部子命令）");
        println!();
        println!("参数:");
        println!("  <binary>              目标二进制（Mach-O/ELF/PE，含 Dart AOT 快照）");
        println!("                         支持 .app / .framework 目录，自动定位内部二进制");
        println!("  <out_dir>             输出目录（自动创建）");
        println!();
        println!("选项:");
        println!("  --sdk-profile PATH     强制指定 SDK Profile（默认: 内嵌 26 版，按版本指纹自动识别）");
        println!("  --platform-profile PATH 强制指定平台 Profile（默认: 按容器+架构自动选择）");
        println!("  --decompile            额外产出 dart/ 伪 Dart（实验性：已做 if/else 与循环结构化）");
        println!("  --lib PATTERN          只导出这些库（可重复；库名前缀即整个包）");
        println!("  --class PATTERN        只导出这些类（可重复）");
        println!("  --func PATTERN         只导出这些函数（可重复，可写 Class.method）");
        println!("  --fuzzy                上面三个模式串改为子串匹配（默认精确）");
        println!();
        println!("  -h, --help            显示此帮助");
        println!("  -V, --version         显示版本");
        println!();
        println!("输出:");
        println!("  ida_script/    IDA 命名脚本 + 结构头（addNames.py / ida_dart_struct.h）");
        println!("  r2_script/     radare2 命名脚本 + 结构头（addNames.r2 / r2_dart_struct.h）");
        println!("  frida.js       Frida 运行时 Classes 数组模板");
        println!("  asm/           capstone 反汇编 + IL 注释（arm64）");
        println!("  text/          pp · objs · strings · libs · classes · functions ·");
        println!("                 arrays · maps · call_edges（各类文本 dump）");
        println!("  callgraph.dot  已命名函数之间的直接调用图（Graphviz）");
        println!("  dart/          --decompile 时的伪 Dart（已结构化 if/else 与循环，实验性）");
        println!();
        println!("示例:");
        println!("  dae App.app out/");
        println!("  dae app.dylib out/ --sdk-profile profiles/sdk/dart-3.3.4-w64-no-compressed.json");
    } else {
        println!("dae {} — static Dart AOT snapshot debug-info exporter (Dart 2.7–3.14β; Mach-O/ELF/PE, x64/arm64)", env!("GIT_VERSION"));
        println!("https://github.com/ejfkdev/dae");
        println!();
        println!("usage: dae <binary> <out_dir> [options]        # full or filtered export");
        println!("       dae <subcommand> <binary> [options]     # progressive: list first, then");
        println!("                                               decompile one class/library");
        println!("                                               (`dae help` lists every subcommand)");
        println!();
        println!("arguments:");
        println!("  <binary>              target binary (Mach-O/ELF/PE with a Dart AOT snapshot);");
        println!("                         accepts .app / .framework directories (locates the binary inside)");
        println!("  <out_dir>             output directory (created if missing)");
        println!();
        println!("options:");
        println!("  --sdk-profile PATH     force an SDK profile (default: 26 embedded, auto-detected by version fingerprint)");
        println!("  --platform-profile PATH force a platform profile (default: auto by container + arch)");
        println!("  --decompile            also emit dart/ pseudocode (experimental; if/else + loops structured)");
        println!("  --lib PATTERN          export only these libraries (repeatable; a prefix = whole package)");
        println!("  --class PATTERN        export only these classes (repeatable)");
        println!("  --func PATTERN         export only these functions (repeatable; Class.method works)");
        println!("  --fuzzy                make the three patterns substring matches (default: exact)");
        println!("  -h, --help            show this help");
        println!("  -V, --version         show version");
        println!();
        println!("progressive (writes no full export): dae info | libs | classes | functions |");
        println!("  strings | fields | largest | callers | disasm | getclass | getmethod | getlib -- see `dae help`");
        println!();
        println!("outputs:");
        println!("  ida_script/    IDA naming script + struct header (addNames.py / ida_dart_struct.h)");
        println!("  r2_script/     radare2 naming script + struct header (addNames.r2 / r2_dart_struct.h)");
        println!("  frida.js       Frida runtime Classes array template");
        println!("  asm/           capstone disassembly + IL comments (arm64)");
        println!("  text/          pp, objs, strings, libs, classes, functions,");
        println!("                 arrays, maps, call_edges (all text dumps)");
        println!("  callgraph.dot  direct-call graph between named functions (Graphviz)");
        println!("  dart/          per-function pseudocode (with --decompile, experimental)");
        println!();
        println!("examples:");
        println!("  dae App.app out/");
        println!("  dae app.dylib out/ --sdk-profile profiles/sdk/dart-3.3.4-w64-no-compressed.json");
    }
}
