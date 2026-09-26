//! 容器适配层：统一成「(symbol → file_offset) 映射 + text 段 VM 地址」。
//! v1: Mach-O（fat/thin，symtab）；ELF/PE 见同目录后续模块。

pub mod elf;
pub mod macho;
pub mod pe;

use crate::profile::PlatformProfile;
use std::collections::HashMap;

pub const MH_MAGIC_64: u32 = 0xFEED_FACF;
pub const FAT_MAGIC: u32 = 0xCAFE_BABE;
pub const ELF_MAGIC: u32 = 0x464C_457F; // 0x7F E L F
pub const PE_MAGIC: u32 = 0x0000_5A4D; // MZ

/// 按魔数探测容器类型（fat Mach-O 魔数为大端存储，其余按小端字节序解释）
pub fn detect_container(data: &[u8]) -> Option<&'static str> {
    if data.len() < 4 {
        return None;
    }
    let b = [data[0], data[1], data[2], data[3]];
    let be = u32::from_be_bytes(b);
    let le = u32::from_le_bytes(b);
    // fat：四种大端魔数
    if matches!(be, FAT_MAGIC | 0xCAFE_BABF | 0xBEBA_FECA | 0xBFBA_FECA) {
        return Some("macho");
    }
    if le == MH_MAGIC_64 || be == MH_MAGIC_64 {
        return Some("macho");
    }
    if be == ELF_MAGIC || le == ELF_MAGIC {
        return Some("elf");
    }
    if le == PE_MAGIC {
        return Some("pe");
    }
    None
}

pub struct ContainerInfo {
    /// symbol → file offset
    pub symbols: HashMap<String, u64>,
    /// __TEXT 段 VM 地址（r2 addNames.r2 的 app.base 来源）
    pub text_vmaddr: Option<u64>,
    /// CPU 类型（Mach-O cputype）
    pub cputype: Option<u32>,
}

pub fn load_container(
    pp: &PlatformProfile,
    data: &[u8],
) -> Result<ContainerInfo, String> {
    match pp.container.kind.as_str() {
        "macho" => macho::parse_macho(data),
        "elf" => elf::parse_elf(data),
        "pe" => pe::parse_pe(data),
        other => Err(format!(
            "平台 Profile 指定容器 {other:?} 未实现（支持 macho/elf/pe）"
        )),
    }
}

/// 快照魔数 [f5 f5 dc dc]（Dart Snapshot::kMagic 的小端字节序）扫描回退：
/// 符号表被剥离（dart2native exe）或裸快照（app-jit）时，按位置定位 VM/ISO 段
/// （文件内偏移小者=VM 快照、大者=ISO 快照——生成器布局下成立）。
pub fn fallback_snapshot_offsets(data: &[u8]) -> Option<(u64, u64)> {
    fallback_snapshot_offsets_in(data, 0, data.len())
}

/// 同上，但只在 [lo, hi) 内扫描。fat Mach-O 必须限定在被分析切片内——否则
/// 另一架构切片的快照会先命中（实测 universal 的 App.framework：x64 切片里
/// 的数据段偏移更小，会被误当成 arm64 的 VM/ISO 偏移）。
pub fn fallback_snapshot_offsets_in(data: &[u8], lo: usize, hi: usize) -> Option<(u64, u64)> {
    let magic: [u8; 4] = [0xf5, 0xf5, 0xdc, 0xdc];
    let hi = hi.min(data.len());
    let mut poses = Vec::new();
    let mut i = lo;
    while i + 4 <= hi {
        if data[i..i + 4] == magic {
            // 快照外层：magic + length(i64) + kind(i64)，kind 应在 1..8
            if i + 20 <= data.len() {
                let kind = i64::from_le_bytes(data[i + 12..i + 20].try_into().unwrap());
                if (1..=8).contains(&kind) {
                    poses.push(i as u64);
                    i += 4;
                    continue;
                }
            }
        }
        i += 1;
    }
    poses.sort_unstable();
    if poses.len() >= 2 {
        Some((poses[0], poses[poses.len() - 1]))
    } else if let Some(&p) = poses.first() {
        // 3.13+ 单快照：VM/ISO 合并，同一入口（引擎按 format.single_snapshot 处理）
        Some((p, p))
    } else {
        None
    }
}

/// 由 Platform Profile 取所需符号的文件偏移（缺一个就报错）；
/// 主符号集不全时回退备用集（symbols_alt，如 3.13 单快照三段式符号）
pub fn required_symbols(
    info: &ContainerInfo,
    pp: &PlatformProfile,
) -> Result<(u64, u64, u64), String> {
    let get = |_name: &str, sym: &str| -> Option<u64> {
        info.symbols.get(sym).copied()
    };
    let try_set = |sn: &crate::profile::SymbolNames| -> Option<(u64, u64, u64)> {
        Some((
            get("vm_data", &sn.vm_data)?,
            get("isolate_data", &sn.isolate_data)?,
            get("isolate_instructions", &sn.isolate_instructions)?,
        ))
    };
    if let Some(v) = try_set(&pp.symbols) {
        return Ok(v);
    }
    if let Some(alt) = &pp.symbols_alt {
        if let Some(v) = try_set(alt) {
            return Ok(v);
        }
    }
    Err(format!(
        "平台 Profile 需要的符号 {}/{}/{} 未在二进制符号表中找到（平台 profile: {}）",
        pp.symbols.vm_data, pp.symbols.isolate_data, pp.symbols.isolate_instructions, pp.name
    ))
}

/// 可执行文件尾部 trailer 里的快照偏移。
///
/// 老版本 `dart compile exe`（2.12–2.14 / 3.3.4 这批 macOS x64 `hello_*.exe`）把快照
/// 作为**独立容器**（实测是 ELF）贴在可执行文件尾部，并在最后 16 字节写下
/// `[snapshot_offset][kAppJITMagicNumber]`（SDK runtime/bin/snapshot_utils.cc
/// TryReadAppendedAppSnapshotElf）。内层容器自带符号表——只按可执行文件自身的符号找不到
/// 快照，就会退化成"地址不可得"，反汇编的是错的字节。
fn appended_blob_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 16 {
        return None;
    }
    let tail = &data[data.len() - 16..];
    let off = u64::from_le_bytes(tail[..8].try_into().ok()?) as usize;
    let magic = u32::from_le_bytes(tail[8..12].try_into().ok()?);
    // kAppJITMagicNumber 的小端字节序（dc dc f6 f6）
    if magic != 0xf6_f6_dc_dc || off == 0 || off >= data.len() {
        return None;
    }
    Some(off)
}

/// 内嵌 blob（`base` 起）里按符号名取 (vm, iso, instr) 的**绝对文件偏移**。
/// blob 可能是 ELF、Mach-O 或 PE——生成器的 `snapshot.aot` 在不同平台/年代不同
/// （实测 arm64 的 3.3.4 内嵌的是 ELF，x64 的 2.13.4 也是 ELF，新 macOS 是 Mach-O dylib）。
pub fn blob_symbols_at(
    data: &[u8],
    base: usize,
    pp: &PlatformProfile,
) -> Option<(u64, u64, u64)> {
    if base >= data.len() {
        return None;
    }
    let sub = &data[base..];
    let info = if sub.starts_with(&[0x7f, b'E', b'L', b'F']) {
        crate::platform::elf::parse_elf(sub).ok()?
    } else if sub.len() >= 4 && sub[..4] == [0xcf, 0xfa, 0xed, 0xfe] {
        crate::platform::macho::parse_macho(sub).ok()?
    } else if sub.len() >= 2 && sub[..2] == [0x4d, 0x5a] {
        crate::platform::pe::parse_pe(sub).ok()?
    } else {
        return None;
    };
    let get = |sn: &crate::profile::SymbolNames| -> Option<(u64, u64, u64)> {
        Some((
            // 内层容器的符号偏移是相对容器起点的，加回 base 才是文件偏移
            *info.symbols.get(&sn.vm_data)? + base as u64,
            *info.symbols.get(&sn.isolate_data)? + base as u64,
            *info.symbols.get(&sn.isolate_instructions)? + base as u64,
        ))
    };
    if let Some(v) = get(&pp.symbols) {
        return Some(v);
    }
    if let Some(alt) = &pp.symbols_alt {
        if let Some(v) = get(alt) {
            return Some(v);
        }
    }
    None
}

/// 尾部 trailer 指向的内嵌容器里的快照符号
pub fn appended_blob_symbols(
    data: &[u8],
    pp: &PlatformProfile,
) -> Option<(u64, u64, u64)> {
    blob_symbols_at(data, appended_blob_offset(data)?, pp)
}

/// 定位 VM/ISO/指令段文件偏移，四层依次尝试：
/// 1. **符号表**（`symbols` → `symbols_alt`）：最精确，指令段基准直接来自符号值；
/// 2. **内嵌快照**（Mach-O `LC_NOTE __dart_app_snap`）：`dart compile exe` 把 AOT 快照
///    贴在可执行文件尾部且不留符号，此时数据段在 blob 内魔数扫描、指令段取内嵌
///    dylib 的 `__text` 段起始。**跳过这一层会让所有函数地址落到错误位置**
///    （instr=0 时 pc_offset 被当成文件偏移，反汇编到别的代码上）；
/// 3. **切片内魔数扫描**：只拿到 VM/ISO，指令段不可得（返回 used_fallback=true，
///    上层据此禁用地址相关产物）。
///
/// 返回 ((vm, iso, instr), 是否回退)。
pub fn locate_snapshots(
    data: &[u8],
    pp: &PlatformProfile,
) -> Result<((u64, u64, u64), bool), String> {
    let info = load_container(pp, data)?;
    if let Ok(v) = required_symbols(&info, pp) {
        return Ok((v, false));
    }
    // 魔数扫描限定在被分析切片内（fat 二进制里另一个架构的切片不能被扫到）
    let (lo, hi) = if pp.container.kind == "macho" {
        crate::platform::macho::fat_slice_range(data)
    } else {
        (0, data.len())
    };
    // 尾部内嵌容器（老版本 `dart compile exe`）：内层自带符号表，指令段基准直接可读
    if let Some(v) = appended_blob_symbols(data, pp) {
        return Ok((v, false));
    }
    // LC_NOTE `__dart_app_snap` 指向的内嵌 blob：可能是 ELF（带符号，直接用）
    // 也可能是 Mach-O dylib（不带符号，退化为"数据段魔数扫描 + 内嵌 __text 段起始"）
    if let Some(app) = crate::platform::macho::appended_dart_snapshot(data) {
        if let Some(v) = blob_symbols_at(data, app.blob_off, pp) {
            return Ok((v, false));
        }
        if let (Some(text_off), Some((vm, iso))) = (
            app.text_off,
            fallback_snapshot_offsets_in(data, app.blob_off, app.blob_end),
        ) {
            return Ok(((vm, iso, text_off), false));
        }
    }
    if let Some((vm, iso)) = fallback_snapshot_offsets_in(data, lo, hi) {
        return Ok(((vm, iso, 0), true));
    }
    Err("平台符号缺失且快照魔数扫描回退失败".to_string())
}