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
const CPU_TYPE_ARM64: u32 = 0x0100_000C;

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