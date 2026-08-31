//! Dart AOT 快照调试信息导出工具（配置驱动）。
//!
//! 用法:
//!   dae <binary> <out_dir> [--sdk-profile P] [--platform-profile P] [--no-asm]

use dae::analyzer::Analyzer;
use dae::export;
use dae::platform;
use dae::profile::{
    parse_platform, parse_sdk, PlatformProfile, SdkProfile,
};
use std::path::PathBuf;

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

const PLATFORM_MACHO_ARM64: &str = include_str!("../profiles/platform/macho-arm64.json");
const PLATFORM_ELF_ARM64: &str = include_str!("../profiles/platform/elf-arm64.json");
const PLATFORM_ELF_X64: &str = include_str!("../profiles/platform/elf-x64.json");
const PLATFORM_MACHO_X64: &str = include_str!("../profiles/platform/macho-x64.json");
const PLATFORM_PE_X64: &str = include_str!("../profiles/platform/pe-x64.json");
const PLATFORM_PE_ARM64: &str = include_str!("../profiles/platform/pe-arm64.json");

fn main() {
    let lang = dae::locale::detect();
    let s = dae::locale::messages(lang);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut positional: Vec<String> = Vec::new();
    let mut sdk_override: Option<PathBuf> = None;
    let mut platform_override: Option<PathBuf> = None;
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

    if let Err(e) = run(bin, out, sdk_override.as_deref(), platform_override.as_deref(), &s) {
        eprintln!("{}: {e}", s.err_prefix);
        std::process::exit(1);
    }
}

fn run(
    bin: &str,
    out: &str,
    sdk_override: Option<&std::path::Path>,
    platform_override: Option<&std::path::Path>,
    s: &dae::locale::Messages,
) -> Result<(), String> {
    let since = std::time::Instant::now();
    let bin_path = resolve_binary(bin, s)?;
    let data = std::fs::read(&bin_path)
        .map_err(|e| format!("{} {bin_path}: {e}", s.err_read_binary))?;
    if std::env::var("DART_AOT_TIMINGS").is_ok() {
        eprintln!("[timing] 读文件({} MB): {:?}", data.len() >> 20, since.elapsed());
    }

    // 平台 Profile：显式覆盖或按容器+架构自动选择
    let plat_storage;
    let platform: PlatformProfile = if let Some(p) = platform_override {
        let c = std::fs::read_to_string(p).map_err(|e| format!("{}{e}", s.err_read_platform))?;
        plat_storage = parse_platform(&c)?;
        plat_storage
    } else {
        let kind = platform::detect_container(&data).ok_or_else(|| {
            // 裸 JIT 快照（app-jit）以 kMessageMagic（dc dc f6 f6）打头，无容器
            if data.len() >= 4 && data[..4] == [0xdc, 0xdc, 0xf6, 0xf6] {
                s.err_bare_jit.to_string()
            } else {
                s.err_container.to_string()
            }
        })?;
        let arch = match kind {
            "macho" => {
                let slice = platform::macho::fat_slice_offset(&data);
                if slice + 8 > data.len() {
                    None
                } else {
                    let cputype =
                        u32::from_le_bytes(data[slice + 4..slice + 8].try_into().unwrap());
                    match cputype {
                        0x0100_000C => Some("arm64"),
                        0x0100_0007 => Some("x64"),
                        0x0000_000C => Some("arm"),
                        _ => None,
                    }
                }
            }
            "elf" => {
                let m = u16::from_le_bytes([data[18], data[19]]);
                match m {
                    62 => Some("x64"),
                    183 => Some("arm64"),
                    40 => Some("arm"),
                    243 => Some("riscv"),
                    _ => None,
                }
            }
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
        match (kind, arch) {
            ("macho", Some("arm64")) => {
                static PARSED: std::sync::OnceLock<PlatformProfile> = std::sync::OnceLock::new();
                PARSED
                    .get_or_init(|| parse_platform(PLATFORM_MACHO_ARM64).expect("内嵌平台 profile 损坏"))
            }
            ("elf", Some("arm64")) => {
                static PARSED: std::sync::OnceLock<PlatformProfile> = std::sync::OnceLock::new();
                PARSED
                    .get_or_init(|| parse_platform(PLATFORM_ELF_ARM64).expect("内嵌平台 profile 损坏"))
            }
            ("elf", Some("x64")) => {
                static PARSED: std::sync::OnceLock<PlatformProfile> = std::sync::OnceLock::new();
                PARSED
                    .get_or_init(|| parse_platform(PLATFORM_ELF_X64).expect("内嵌平台 profile 损坏"))
            }
            ("macho", Some("x64")) => {
                static PARSED: std::sync::OnceLock<PlatformProfile> = std::sync::OnceLock::new();
                PARSED
                    .get_or_init(|| parse_platform(PLATFORM_MACHO_X64).expect("内嵌平台 profile 损坏"))
            }
            ("pe", Some("x64")) => {
                static PARSED: std::sync::OnceLock<PlatformProfile> = std::sync::OnceLock::new();
                PARSED
                    .get_or_init(|| parse_platform(PLATFORM_PE_X64).expect("内嵌平台 profile 损坏"))
            }
            ("pe", Some("arm64")) => {
                static PARSED: std::sync::OnceLock<PlatformProfile> = std::sync::OnceLock::new();
                PARSED
                    .get_or_init(|| parse_platform(PLATFORM_PE_ARM64).expect("内嵌平台 profile 损坏"))
            }
            _ => {
                return Err(format!(
                    "container {kind} arch {arch:?}: {}",
                    s.err_platform_missing
                ));
            }
        }
        .clone()
    };

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
    let analyzer = Analyzer::new_located(&data, sdk, &platform, snap_offs, used_fallback)?;
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

    let summary = export::run(&analyzer, std::path::Path::new(out))?;
    println!("{} {}:", s.export_done, out);
    println!("  r2_script/addNames.r2     {} {}", summary.r2_functions, s.sum_r2);
    println!("  ida_script/addNames.py    {} {}", summary.ida_functions, s.sum_ida);
    println!("  blutter_frida.js          {} {}", summary.frida_classes, s.sum_frida);
    if summary.asm_enabled {
        println!("  asm/                      {} {}", summary.asm_functions, s.sum_asm);
    }
    println!("  pp.txt                    {} {}", summary.pp_entries, s.sum_pp);
    println!("  objs.txt                  {} {}", summary.objs_instances, s.sum_objs);

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
    Ok(())
}

fn print_help(s: &dae::locale::Messages) {
    if s.lang == dae::locale::Lang::Zh {
        // 中文语系
        println!("dae — Dart AOT 快照调试信息静态导出工具");
        println!();
        println!("用法: dae <binary> <out_dir> [选项]");
        println!();
        println!("参数:");
        println!("  <binary>              目标二进制文件（Mach-O/ELF/PE，含 Dart AOT 快照）");
        println!("                         支持直接传入 .app 目录（自动查找 Flutter 二进制）");
        println!("  <out_dir>             输出目录（自动创建）");
        println!();
        println!("选项:");
        println!("  --sdk-profile PATH     强制指定 SDK Profile（默认: 内嵌 26 版，自动识别 Dart 版本）");
        println!("  --platform-profile PATH 平台 Profile JSON（默认: 按容器+架构自动选择）");
        println!("  -h, --help            显示此帮助");
        println!("  -V, --version         显示版本");
        println!();
        println!("输出文件:");
        println!("  r2_script/addNames.r2  radare2 函数命名脚本");
        println!("  ida_script/addNames.py  IDA 命名脚本（IDAPython + Dart 结构头）");
        println!("  blutter_frida.js       Frida 运行时 Classes 数组");
        println!("  asm/                   capstone 反汇编 + IL 注释（arm64）");
        println!("  pp.txt                 对象池条目");
        println!("  objs.txt               用户类实例递归 dump");
        println!();
        println!("智能路径解析:");
        println!("  macOS Flutter:  xxx.app → App.framework/App");
        println!("  iOS Flutter:    xxx.app → App（同结构）");
        println!("  dart2native:    xxx.exe / xxx（直接使用）");
        println!();
        println!("语言: 跟随系统语系自动选择（中文语系输出中文，其余英文）；可用 DAE_LANG=zh|en 强制");
        println!("Profile 文档: docs/PROFILES.zh.md | profiles/");
        println!("版本列表: 内置 26 个 Dart 版本（1.24–3.14β），自动识别版本");
        println!("项目主页: https://github.com/ejfkdev/dae");
        println!();
        println!("示例:");
        println!("  dae App.app out/");
        println!("  dae app.dylib out/ --sdk-profile profiles/sdk/dart-3.3.4-w64-no-compressed.json");
        println!();
        println!("使用产物: 见 README「使用导出产物」一节（IDA: File → Script file… 选择 ida_script/addNames.py）");
    } else {
        println!("dae — static Dart AOT snapshot debug-info exporter");
        println!();
        println!("usage: dae <binary> <out_dir> [options]");
        println!();
        println!("arguments:");
        println!("  <binary>              target binary (Mach-O/ELF/PE with a Dart AOT snapshot)");
        println!("                         accepts an .app directory directly (locates the Flutter binary)");
        println!("  <out_dir>             output directory (created if missing)");
        println!();
        println!("options:");
        println!("  --sdk-profile PATH     force an SDK profile (default: 26 embedded, auto-detected)");
        println!("  --platform-profile PATH platform profile JSON (default: auto by container + arch)");
        println!("  -h, --help            show this help");
        println!("  -V, --version         show version");
        println!();
        println!("outputs:");
        println!("  r2_script/addNames.r2  radare2 naming script");
        println!("  ida_script/addNames.py  IDA naming script (IDAPython + Dart struct header)");
        println!("  blutter_frida.js       Frida runtime Classes array");
        println!("  asm/                   capstone disassembly + IL comments (arm64)");
        println!("  pp.txt                 object pool entries");
        println!("  objs.txt               recursive user class instance dump");
        println!();
        println!("smart path resolution:");
        println!("  macOS Flutter:  xxx.app -> App.framework/App");
        println!("  iOS Flutter:    xxx.app -> App (same layout)");
        println!("  dart2native:    xxx.exe / xxx (used directly)");
        println!();
        println!("language: follows the system locale (Chinese locales print Chinese, others English); override with DAE_LANG=zh|en");
        println!("profile docs: docs/PROFILES.md | profiles/");
        println!("versions: 26 embedded Dart versions (1.24-3.14beta), auto-detected");
        println!("homepage: https://github.com/ejfkdev/dae");
        println!();
        println!("examples:");
        println!("  dae App.app out/");
        println!("  dae app.dylib out/ --sdk-profile profiles/sdk/dart-3.3.4-w64-no-compressed.json");
        println!();
        println!("using outputs: see README 'Using the outputs' (IDA: File -> Script file... then pick ida_script/addNames.py)");
    }
}

/// 智能路径解析：如果输入是 .app 目录，自动查找 Flutter 二进制。
fn resolve_binary(path: &str, s: &dae::locale::Messages) -> Result<String, String> {
    let p = std::path::Path::new(path);
    if p.is_dir() {
        // macOS Flutter: xxx.app/Contents/Frameworks/App.framework/App
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
            candidates.iter().map(|c| c.to_string_lossy()).collect::<Vec<_>>().join(", ")
        ));
    }
    Ok(path.to_string())
}