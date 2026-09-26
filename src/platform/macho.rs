//! Mach-O（fat/thin 64 位）：fat 切片定位 + LC_SYMTAB 符号表 → file offset 映射。
//! 与参考实现 dart_aot_full.py 的 fat_slice_offset / macho_symbols 行为一致。

use super::ContainerInfo;
use std::collections::HashMap;

const MH_MAGIC_64: u32 = 0xFEED_FACF;
const FAT_MAGIC: u32 = 0xCAFE_BABE;
const FAT_MAGIC_64: u32 = 0xCAFE_BABF;
const FAT_CIGAM: u32 = 0xBEBA_FECA;
const FAT_CIGAM_64: u32 = 0xBFBA_FECA;
const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x02;
const LC_NOTE: u32 = 0x31;
const CPU_TYPE_ARM64: u32 = 0x0100_000C;
/// Dart 在内嵌快照 blob 的 LC_NOTE 里写的 data_owner（见 SDK runtime/bin/snapshot_utils.cc）
const DART_APP_SNAP_NOTE: &[u8] = b"__dart_app_snap";

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..8].try_into().unwrap())
}

/// 若为 fat，返回 arm64 切片的偏移；否则 0。
pub fn fat_slice_offset(data: &[u8]) -> usize {
    if data.len() < 8 {
        return 0;
    }
    let magic = be32(&data[..4]);
    if !matches!(magic, FAT_MAGIC | FAT_MAGIC_64 | FAT_CIGAM | FAT_CIGAM_64) {
        return 0;
    }
    let be = matches!(magic, FAT_MAGIC | FAT_MAGIC_64);
    let n = if be { be32(&data[4..8]) } else { le32(&data[4..8]) } as usize;
    for i in 0..n {
        let p = 8 + i * 20;
        if p + 20 > data.len() {
            break;
        }
        let slice = &data[p..p + 20];
        let ct = if be { be32(&slice[..4]) } else { le32(&slice[..4]) };
        let off = if be { be32(&slice[8..12]) } else { le32(&slice[8..12]) };
        if ct == CPU_TYPE_ARM64 {
            return off as usize;
        }
    }
    let p = data[8..28].get(8..12).unwrap_or(&[0; 4]);
    let off = if be { be32(p) } else { le32(p) };
    off as usize
}

/// 解析（fat 切片后的）Mach-O：symbol → file offset、__TEXT VM 地址、cputype。
pub fn parse_macho(data: &[u8]) -> Result<ContainerInfo, String> {
    let slice_off = fat_slice_offset(data);
    if data.len() < slice_off + 24 {
        return Err("Mach-O 头越界".into());
    }
    if le32(&data[slice_off..slice_off + 4]) != MH_MAGIC_64 {
        return Err("非 64 位 Mach-O（仅支持 MH_MAGIC_64）".into());
    }
    let cputype = Some(le32(&data[slice_off + 4..slice_off + 8]));
    let ncmds = le32(&data[slice_off + 16..slice_off + 20]) as usize;
    let mut p = slice_off + 32;
    let mut segs: Vec<(u64, u64, u64)> = Vec::new(); // (va, vsize, foff)
    let mut symtab: Option<(usize, usize, usize, usize)> = None; // symoff, nsyms, stroff, strsize
    let mut text_vmaddr: Option<u64> = None;
    for _ in 0..ncmds {
        if p + 8 > data.len() {
            break;
        }
        let cmd = le32(&data[p..p + 4]);
        let cmdsize = le32(&data[p + 4..p + 8]) as usize;
        if cmdsize < 8 {
            break;
        }
        match cmd {
            LC_SEGMENT_64 => {
                if p + 56 <= data.len() {
                    let segname = &data[p + 8..p + 24];
                    let va = le64(&data[p + 24..p + 32]);
                    let vsize = le64(&data[p + 32..p + 40]);
                    let foff = le64(&data[p + 40..p + 48]);
                    if segname.starts_with(b"__TEXT") {
                        text_vmaddr = Some(va);
                    }
                    segs.push((va, vsize, foff));
                }
            }
            LC_SYMTAB => {
                if p + 24 <= data.len() {
                    let symoff = le32(&data[p + 8..p + 12]) as usize;
                    let nsyms = le32(&data[p + 12..p + 16]) as usize;
                    let stroff = le32(&data[p + 16..p + 20]) as usize;
                    let strsize = le32(&data[p + 20..p + 24]) as usize;
                    symtab = Some((symoff, nsyms, stroff, strsize));
                }
            }
            _ => {}
        }
        p += cmdsize;
    }
    let mut symbols = HashMap::new();
    if let Some((symoff, nsyms, stroff, strsize)) = symtab {
        for i in 0..nsyms {
            let e = slice_off + symoff + i * 16;
            if e + 16 > data.len() {
                break;
            }
            let entry = &data[e..e + 16];
            let n_strx = le32(&entry[..4]) as usize;
            if n_strx == 0 || n_strx >= strsize {
                continue;
            }
            let n_value = le64(&entry[8..16]);
            let base = slice_off + stroff;
            if base + n_strx >= data.len() {
                continue;
            }
            let name = read_cstr(data, base + n_strx);
            if name.is_empty() {
                continue;
            }
            for (va, vsize, foff) in &segs {
                if *va <= n_value && n_value < *va + *vsize {
                    symbols.insert(name, slice_off as u64 + *foff + (n_value - *va));
                    break;
                }
            }
        }
    }
    Ok(ContainerInfo {
        symbols,
        text_vmaddr,
        cputype,
    })
}

fn read_cstr(data: &[u8], mut pos: usize) -> String {
    let mut end = pos;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    pos = pos.min(end);
    let s = &data[pos..end];
    match std::str::from_utf8(s) {
        Ok(v) => v.to_string(),
        Err(_) => String::new(),
    }
}

/// fat 文件里被分析**切片**的范围 [start, end)。thin 文件返回整个文件。
/// 用途：魔数扫描限定在本切片内——否则 fat 里另一个架构的切片会先被扫到，
/// 导致 VM/ISO 偏移取自错误的架构（x64 切片的快照被当成 arm64 的）。
pub fn fat_slice_range(data: &[u8]) -> (usize, usize) {
    let start = fat_slice_offset(data);
    if start == 0 {
        return (0, data.len());
    }
    if data.len() < 8 {
        return (start, data.len());
    }
    let magic = be32(&data[..4]);
    let be = matches!(magic, FAT_MAGIC | FAT_MAGIC_64);
    let n = if be { be32(&data[4..8]) } else { le32(&data[4..8]) } as usize;
    let mut end = data.len();
    for i in 0..n {
        let p = 8 + i * 20;
        if p + 20 > data.len() {
            break;
        }
        let slice = &data[p..p + 20];
        let off = if be { be32(&slice[8..12]) } else { le32(&slice[8..12]) } as usize;
        let size = if be { be32(&slice[12..16]) } else { le32(&slice[12..16]) } as usize;
        // 取紧邻选中切片之后的下一个切片起点作为上界
        if off > start && off < end {
            end = off;
        }
        let _ = size;
    }
    (start, end)
}

/// 迭代 thin Mach-O（起点 `off`）的段/节：对每节回调 (sectname, segment fileoff, addr, size, section fileoff)。
/// 返回节数量。
fn each_section(
    data: &[u8],
    off: usize,
    mut f: impl FnMut(&str, u64, u64, u64, u64),
) -> usize {
    if off + 32 > data.len() || le32(&data[off..off + 4]) != MH_MAGIC_64 {
        return 0;
    }
    let ncmds = le32(&data[off + 16..off + 20]) as usize;
    let mut p = off + 32;
    let mut count = 0usize;
    for _ in 0..ncmds {
        if p + 8 > data.len() {
            break;
        }
        let cmd = le32(&data[p..p + 4]);
        let cmdsize = le32(&data[p + 4..p + 8]) as usize;
        if cmdsize < 8 {
            break;
        }
        if cmd == LC_SEGMENT_64 && p + 72 <= data.len() {
            let seg_fo = le64(&data[p + 40..p + 48]);
            let nsects = le32(&data[p + 64..p + 68]) as usize;
            for s in 0..nsects {
                let q = p + 72 + s * 80;
                if q + 80 > data.len() {
                    break;
                }
                let name = read_cstr(data, q);
                let addr = le64(&data[q + 32..q + 40]);
                let size = le64(&data[q + 40..q + 48]);
                let fo = le32(&data[q + 48..q + 52]) as u64;
                f(&name, seg_fo, addr, size, fo);
                count += 1;
            }
        }
        p += cmdsize;
    }
    count
}

/// 内嵌 AOT 快照（macOS 的 `dart compile exe` / Flutter 产物的 appended snapshot）。
///
/// 文件尾的 `LC_NOTE __dart_app_snap` 指向一段 blob；blob 自身是一个 Mach-O dylib
/// （ID `snapshot.aot`），其 `__text` 段就是**指令镜像**（`start_pc` = 段起始），
/// `__const` 段是数据镜像。SDK 侧见 runtime/bin/snapshot_utils.cc 的
/// TryReadAppendedAppSnapshotFromMachO + macho_loader.cc 的 ResolveSymbols。
pub struct AppendedSnap {
    /// blob 在文件中的起点（fat 切片偏移已计入）
    pub blob_off: usize,
    /// blob 终点（魔数扫描上界）
    pub blob_end: usize,
    /// 指令镜像起始的**文件偏移**（可直接当 instr_off 用：pc_offset 以 __text 段起始为基准）。
    /// None = blob 不是 Mach-O（实测有内嵌 ELF 的场合），此时只能靠符号表定位。
    pub text_off: Option<u64>,
}

/// 找内嵌快照；无 LC_NOTE / 无内嵌 Mach-O / 无 __text 时返回 None。
pub fn appended_dart_snapshot(data: &[u8]) -> Option<AppendedSnap> {
    let slice_off = fat_slice_offset(data);
    if slice_off + 32 > data.len() || le32(&data[slice_off..slice_off + 4]) != MH_MAGIC_64 {
        return None;
    }
    let ncmds = le32(&data[slice_off + 16..slice_off + 20]) as usize;
    let mut p = slice_off + 32;
    let mut note: Option<(usize, usize)> = None;
    for _ in 0..ncmds {
        if p + 8 > data.len() {
            break;
        }
        let cmd = le32(&data[p..p + 4]);
        let cmdsize = le32(&data[p + 4..p + 8]) as usize;
        if cmdsize < 8 {
            break;
        }
        if cmd == LC_NOTE && p + 40 <= data.len() {
            let owner = &data[p + 8..p + 24];
            if owner.starts_with(DART_APP_SNAP_NOTE) {
                let offset = le64(&data[p + 24..p + 32]) as usize;
                let size = le64(&data[p + 32..p + 40]) as usize;
                note = Some((slice_off + offset, size));
            }
        }
        p += cmdsize;
    }
    let (blob_off, blob_size) = note?;
    let blob_end = (blob_off + blob_size).min(data.len());
    if blob_off >= data.len() {
        return None;
    }
    // blob 本体通常是 Mach-O dylib；__text 段起始即指令镜像基准。
    // 也可能是 ELF（不同年代/平台的内嵌物不同），那就没有 __text 段可找——
    // 此时仍返回 blob 范围，让调用方去解析它的符号表。
    let mut text_off: Option<u64> = None;
    each_section(data, blob_off, |name, _seg_fo, _addr, _size, fo| {
        if text_off.is_none() && name == "__text" {
            text_off = Some(blob_off as u64 + fo);
        }
    });
    Some(AppendedSnap {
        blob_off,
        blob_end,
        text_off,
    })
}

#[cfg(test)]
mod tests {
    use super::fat_slice_offset;

    #[test]
    fn thin_binary_returns_zero() {
        // MH_MAGIC_64 小端
        let data = [0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0];
        assert_eq!(fat_slice_offset(&data), 0);
    }
}