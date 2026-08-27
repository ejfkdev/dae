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

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut positional: Vec<String> = Vec::new();
    let mut sdk_override: Option<PathBuf> = None;
    let mut platform_override: Option<PathBuf> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--sdk-profile" => {
                if i + 1 >= args.len() {
                    eprintln!("错误: --sdk-profile 缺少参数");
                    std::process::exit(2);
                }
                sdk_override = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--platform-profile" => {
                if i + 1 >= args.len() {
                    eprintln!("错误: --platform-profile 缺少参数");
                    std::process::exit(2);
                }
                platform_override = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--help" | "-h" => {
                print_help();
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
        print_help();
        std::process::exit(2);
    }
    let bin = &positional[0];
    let out = &positional[1];

    if let Err(e) = run(bin, out, sdk_override.as_deref(), platform_override.as_deref()) {
        eprintln!("错误: {e}");
        std::process::exit(1);
    }
}

fn run(
    bin: &str,
    out: &str,
    sdk_override: Option<&std::path::Path>,
    platform_override: Option<&std::path::Path>,
) -> Result<(), String> {
    let since = std::time::Instant::now();
    let bin_path = resolve_binary(bin)?;
    let data = std::fs::read(&bin_path).map_err(|e| format!("读二进制失败 {bin_path}: {e}"))?;
    if std::env::var("DART_AOT_TIMINGS").is_ok() {
        eprintln!("[timing] 读文件({} MB): {:?}", data.len() >> 20, since.elapsed());
    }

    // 平台 Profile：显式覆盖或按容器+架构自动选择
    let plat_storage;
    let platform: PlatformProfile = if let Some(p) = platform_override {
        let c = std::fs::read_to_string(p).map_err(|e| format!("读 --platform-profile: {e}"))?;
        plat_storage = parse_platform(&c)?;
        plat_storage
    } else {
        let kind = platform::detect_container(&data).ok_or_else(|| {
            // 裸 JIT 快照（app-jit）以 kMessageMagic（dc dc f6 f6）打头，无容器
            if data.len() >= 4 && data[..4] == [0xdc, 0xdc, 0xf6, 0xf6] {
                "裸 app-JIT 快照（kMessageMagic）没有容器包裹，暂不支持（需 AOT 产物：dart compile aot-snapshot / dart2native / Flutter release 构建）".to_string()
            } else {
                "无法识别容器格式（不是 Mach-O/ELF/PE）".to_string()
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
            _ => {
                return Err(format!(
                    "容器 {kind} 架构 {arch:?} 暂无内嵌平台 Profile，请用 --platform-profile 指定（profiles/platform/ 下新建一份即可）"
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
        dae::profile::detect::detect_or_default(&data, snap_offs)
    };

    if sdk.status != "verified" {
        eprintln!(
            "警告: SDK Profile {} 状态为 unverified（该版本的样本对拍尚未全部完成）。导出结果仅供参考，请以 verified 版本结果为准",
            sdk.abi
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
    println!("导出完成 → {}:", out);
    println!("  r2_script/addNames.r2     {} 条函数名/地址", summary.r2_functions);
    println!("  ida_script/addNames.py    {} 个函数命名 + Dart 结构头", summary.ida_functions);
    println!("  blutter_frida.js          {} 个 Classes 条目", summary.frida_classes);
    if summary.asm_enabled {
        println!("  asm/                      {} 个函数反汇编 + IL", summary.asm_functions);
    }
    println!("  pp.txt                    {} 个对象池条目", summary.pp_entries);
    println!("  objs.txt                  {} 个用户类实例", summary.objs_instances);

    for w in &analyzer.warnings {
        eprintln!("警告: {w}");
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

fn print_help() {
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
    println!("Profile 文档: docs/PROFILES.md | profiles/");
    println!("版本列表: 内置 26 个 Dart 版本（1.24–3.14β），自动识别版本");
    println!("项目主页: https://github.com/ejfkdev/dae");
    println!();
    println!("示例:");
    println!("  dae App.app out/");
    println!("  dae app.dylib out/ --sdk-profile profiles/sdk/dart-3.3.4-w64-no-compressed.json");
}

/// 智能路径解析：如果输入是 .app 目录，自动查找 Flutter 二进制。
fn resolve_binary(path: &str) -> Result<String, String> {
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
            "目录 {path} 内未找到 Flutter 二进制（尝试了 {})",
            candidates.iter().map(|c| c.to_string_lossy()).collect::<Vec<_>>().join(", ")
        ));
    }
    Ok(path.to_string())
}