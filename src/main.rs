//! Dart AOT 快照调试信息导出工具（配置驱动）。
//!
//! 用法:
//!   dae <binary> <out_dir> [--sdk-profile P] [--platform-profile P] [--no-asm]

use dae::analyzer::Analyzer;
use dae::export;
use dae::platform;
use dae::profile::{parse_sdk, PlatformProfile, SdkProfile};
use std::path::PathBuf;

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;


fn main() {
    let lang = dae::locale::detect();
    let s = dae::locale::messages(lang);
    let args: Vec<String> = std::env::args().skip(1).collect();
    // 渐进式模式：`dae <子命令> ...`（见 src/cli.rs）。判定只看第一个参数是否是已知
    // 子命令名——本机文件恰好同名时写 `./info` 即可落回全量导出。
    if let Some(first) = args.first() {
        if dae::cli::is_subcommand(first) {
            std::process::exit(dae::cli::dispatch(&args, lang, &s));
        }
    }
    let mut positional: Vec<String> = Vec::new();
    let mut sel = dae::selection::Selection::default();
    let mut sdk_override: Option<PathBuf> = None;
    let mut platform_override: Option<PathBuf> = None;
    let mut decompile = false;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--sdk-profile" => {
                if i + 1 >= args.len() {
                    eprintln!("{}", s.err_sdk_arg);
                    std::process::exit(2);
                }
                sdk_override = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--platform-profile" => {
                if i + 1 >= args.len() {
                    eprintln!("{}", s.err_platform_arg);
                    std::process::exit(2);
                }
                platform_override = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--decompile" => {
                decompile = true;
                i += 1;
            }
            "--lib" => {
                if i + 1 >= args.len() {
                    eprintln!("--lib 需要一个取值");
                    std::process::exit(2);
                }
                sel.libs.push(args[i + 1].clone());
                i += 2;
            }
            "--class" => {
                if i + 1 >= args.len() {
                    eprintln!("--class 需要一个取值");
                    std::process::exit(2);
                }
                sel.classes.push(args[i + 1].clone());
                i += 2;
            }
            "--func" => {
                if i + 1 >= args.len() {
                    eprintln!("--func 需要一个取值");
                    std::process::exit(2);
                }
                sel.funcs.push(args[i + 1].clone());
                i += 2;
            }
            "--fuzzy" => {
                sel.fuzzy = true;
                i += 1;
            }
            "--help" | "-h" => {
                print_help(&s);
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("dae {}", env!("GIT_VERSION"));
                std::process::exit(0);
            }
            _ => {
                positional.push(args[i].clone());
                i += 1;
            }
        }
    }
    if positional.len() < 2 {
        print_help(&s);
        std::process::exit(2);
    }
    let bin = &positional[0];
    let out = &positional[1];

    if let Err(e) = run(
        bin,
        out,
        sdk_override.as_deref(),
        platform_override.as_deref(),
        decompile,
        &sel,
        &s,
    ) {
        eprintln!("{}: {e}", s.err_prefix);
        std::process::exit(1);
    }
}

#[allow(clippy::too_many_arguments)]
fn run(
    bin: &str,
    out: &str,
    sdk_override: Option<&std::path::Path>,
    platform_override: Option<&std::path::Path>,
    decompile: bool,
    sel: &dae::selection::Selection,
    s: &dae::locale::Messages,
) -> Result<(), String> {
    let since = std::time::Instant::now();
    let bin_path = dae::cli::resolve_binary(bin, s)?;
    let data = std::fs::read(&bin_path)
        .map_err(|e| format!("{} {bin_path}: {e}", s.err_read_binary))?;
    if std::env::var("DART_AOT_TIMINGS").is_ok() {
        eprintln!("[timing] 读文件({} MB): {:?}", data.len() >> 20, since.elapsed());
    }

    // 平台 Profile：显式覆盖或按容器+架构自动选择（与渐进式子命令共用同一份逻辑）
    let platform: PlatformProfile = dae::cli::resolve_platform(&data, platform_override, s)?;

    // 快照偏移定位（自动识别与解析共用同一份结果）
    let (snap_offs, used_fallback) = platform::locate_snapshots(&data, &platform)?;

    // SDK Profile：版本自动识别（hash 指纹 → 结构探针），--sdk-profile 强制覆盖
    let sdk_storage;
    let sdk: &SdkProfile = if let Some(p) = sdk_override {
        let c = std::fs::read_to_string(p).map_err(|e| format!("读 --sdk-profile: {e}"))?;
        sdk_storage = parse_sdk(&c)?;
        &sdk_storage
    } else {
        dae::profile::detect::detect_or_default(&data, snap_offs, s)
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
            "InstructionsTable: first_entry_with_code={} n_entries={} instr_base(file-offset)={:#x}",
            analyzer.first_entry,
            analyzer.pc_offsets.len(),
            analyzer.instr_base
        );
    }

    // 输出目录的绝对路径（不解析软链、不要求已存在，仅把相对路径接到 cwd 上），
    // 便于调用方/脚本直接复制取用最终产物位置。
    let out_abs = std::path::absolute(out)
        .map_err(|e| format!("解析输出目录绝对路径 {out}: {e}"))?;
    let out_display = out_abs.display().to_string();
    if std::env::var("DART_AOT_DEBUG_DEC").is_ok() {
        #[cfg(feature = "asm")]
        {
            dae::decompiler::pool_debug(&analyzer);
        }
    }
    let filtered_libs = dae::selection::filter_libs(&analyzer.build_functions(true), sel);
    if !sel.is_empty() {
        let (nl, nc, nf) = dae::selection::counts(&filtered_libs);
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
    let summary = export::run_with(&analyzer, &out_abs, sel)?;
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
            let st = dae::decompiler::write(&analyzer, &filtered_libs, &out_abs)?;
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
    Ok(())
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
        println!("  strings | largest | callers | disasm | getclass | getmethod | getlib -- see `dae help`");
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
