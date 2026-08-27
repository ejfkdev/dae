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
    let magic: [u8; 4] = [0xf5, 0xf5, 0xdc, 0xdc];
    let mut poses = Vec::new();
    let mut i = 0usize;
    while i + 4 <= data.len() {
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

/// 定位 VM/ISO/指令段文件偏移（symbols → 魔数扫描回退）。
/// 返回 ((vm, iso, instr), 是否回退)。提取自 Analyzer::new，
/// 供自动识别（detect）与解析共用同一份定位逻辑。
pub fn locate_snapshots(
    data: &[u8],
    pp: &PlatformProfile,
) -> Result<((u64, u64, u64), bool), String> {
    let info = load_container(pp, data)?;
    if let Ok(v) = required_symbols(&info, pp) {
        return Ok((v, false));
    }
    if let Some((vm, iso)) = fallback_snapshot_offsets(data) {
        return Ok(((vm, iso, 0), true));
    }
    Err("平台符号缺失且快照魔数扫描回退失败".to_string())
}