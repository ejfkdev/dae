//! ELF 容器适配器（Android libapp.so / Linux）：ELF32/ELF64 little-endian，
//! .symtab（优先）/.dynsym 符号表 → (symbol → file offset)，PT_LOAD 段做 VA 映射。

use super::ContainerInfo;
use std::collections::HashMap;

const SHT_SYMTAB: u32 = 2;
const SHT_DYNSYM: u32 = 11;
const PT_LOAD: u32 = 1;

pub fn parse_elf(data: &[u8]) -> Result<ContainerInfo, String> {
    if data.len() < 52 || &data[..4] != b"\x7fELF" {
        return Err("非 ELF".into());
    }
    let is64 = data[4] == 2;
    if data[5] != 1 {
        return Err("仅支持小端 ELF".into());
    }
    let machine = u16::from_le_bytes([data[18], data[19]]);

    let (phoff, phentsize, phnum): (usize, usize, usize) = if is64 {
        (
            u64::from_le_bytes(data[32..40].try_into().unwrap()) as usize,
            u16::from_le_bytes([data[54], data[55]]) as usize,
            u16::from_le_bytes([data[56], data[57]]) as usize,
        )
    } else {
        (
            u32::from_le_bytes(data[28..32].try_into().unwrap()) as usize,
            u16::from_le_bytes([data[42], data[43]]) as usize,
            u16::from_le_bytes([data[44], data[45]]) as usize,
        )
    };

    // PT_LOAD 段：VA→file 映射
    let mut segments: Vec<(u64, u64, u64)> = Vec::new(); // (p_vaddr, p_filesz, p_offset)
    for i in 0..phnum {
        let p = phoff + i * phentsize;
        if phentsize == 0 || p + 8 > data.len() {
            break;
        }
        if u32::from_le_bytes(data[p..p + 4].try_into().unwrap()) != PT_LOAD {
            continue;
        }
        if is64 {
            if p + 56 > data.len() {
                break;
            }
            segments.push((
                u64::from_le_bytes(data[p + 16..p + 24].try_into().unwrap()),
                u64::from_le_bytes(data[p + 32..p + 40].try_into().unwrap()),
                u64::from_le_bytes(data[p + 8..p + 16].try_into().unwrap()),
            ));
        } else {
            if p + 32 > data.len() {
                break;
            }
            segments.push((
                u32::from_le_bytes(data[p + 8..p + 12].try_into().unwrap()) as u64,
                u32::from_le_bytes(data[p + 16..p + 20].try_into().unwrap()) as u64,
                u32::from_le_bytes(data[p + 4..p + 8].try_into().unwrap()) as u64,
            ));
        }
    }
    let text_vmaddr = segments.first().map(|s| s.0);

    // 节表
    let (shoff, shentsize, shnum, shstrndx): (usize, usize, usize, usize) = if is64 {
        (
            u64::from_le_bytes(data[40..48].try_into().unwrap()) as usize,
            u16::from_le_bytes([data[58], data[59]]) as usize,
            u16::from_le_bytes([data[60], data[61]]) as usize,
            u16::from_le_bytes([data[62], data[63]]) as usize,
        )
    } else {
        (
            u32::from_le_bytes(data[32..36].try_into().unwrap()) as usize,
            u16::from_le_bytes([data[46], data[47]]) as usize,
            u16::from_le_bytes([data[48], data[49]]) as usize,
            u16::from_le_bytes([data[50], data[51]]) as usize,
        )
    };

    struct Sect {
        name: String,
        shtype: u32,
        offset: u64,
        size: u64,
        link: u32,
        entsize: u64,
    }
    let mut sections: Vec<Sect> = Vec::new();
        let mut name_offs: Vec<u32> = Vec::new();
        for _i in 0..shnum {
            let p = shoff + _i * shentsize;
            if shentsize == 0 || p + 4 > data.len() {
                break;
            }
            let name_off = u32::from_le_bytes(data[p..p + 4].try_into().unwrap());
            let (shtype, offset, size, link, entsize): (u32, u64, u64, u32, u64) = if is64 {
                if p + 64 > data.len() {
                    break;
                }
                (
                    u32::from_le_bytes(data[p + 4..p + 8].try_into().unwrap()),
                    u64::from_le_bytes(data[p + 24..p + 32].try_into().unwrap()),
                    u64::from_le_bytes(data[p + 32..p + 40].try_into().unwrap()),
                    u32::from_le_bytes(data[p + 40..p + 44].try_into().unwrap()),
                    u64::from_le_bytes(data[p + 56..p + 64].try_into().unwrap()),
                )
            } else {
                if p + 40 > data.len() {
                    break;
                }
                (
                    u32::from_le_bytes(data[p + 4..p + 8].try_into().unwrap()),
                    u32::from_le_bytes(data[p + 16..p + 20].try_into().unwrap()) as u64,
                    u32::from_le_bytes(data[p + 20..p + 24].try_into().unwrap()) as u64,
                    u32::from_le_bytes(data[p + 24..p + 28].try_into().unwrap()),
                    u32::from_le_bytes(data[p + 36..p + 40].try_into().unwrap()) as u64,
                )
            };
            name_offs.push(name_off);
            sections.push(Sect {
                name: String::new(),
                shtype,
                offset,
                size,
                link,
                entsize,
            });
        }
        // 节名（shstrtab）
        if shstrndx < sections.len() {
            let base = sections[shstrndx].offset as usize;
            for (i, s) in sections.iter_mut().enumerate() {
                s.name = read_cstr(data, base + *name_offs.get(i).unwrap_or(&0) as usize);
            }
        }

    // 符号表：.symtab 优先，其次 .dynsym
    let mut symbols = HashMap::new();
    for want in [SHT_SYMTAB, SHT_DYNSYM] {
        for s in sections.iter() {
            if s.shtype != want {
                continue;
            }
            let strtab = &sections.get(s.link as usize);
            let strtab_base = strtab.map(|t| t.offset as usize).unwrap_or(0);
            let strtab_size = strtab.map(|t| t.size as usize).unwrap_or(0);
            let entry_size = if s.entsize != 0 { s.entsize } else { if is64 { 24 } else { 16 } };
            let count = if entry_size == 0 { 0 } else { (s.size / entry_size) as usize };
            for i in 0..count {
                let p = s.offset as usize + i * entry_size as usize;
                if p + entry_size as usize > data.len() {
                    break;
                }
                let (name_off, value, shndx): (usize, u64, usize) = if is64 {
                    (
                        u32::from_le_bytes(data[p..p + 4].try_into().unwrap()) as usize,
                        u64::from_le_bytes(data[p + 8..p + 16].try_into().unwrap()),
                        u16::from_le_bytes(data[p + 6..p + 8].try_into().unwrap()) as usize,
                    )
                } else {
                    (
                        u32::from_le_bytes(data[p..p + 4].try_into().unwrap()) as usize,
                        u32::from_le_bytes(data[p + 4..p + 8].try_into().unwrap()) as u64,
                        u16::from_le_bytes(data[p + 6..p + 8].try_into().unwrap()) as usize,
                    )
                };
                #[cfg(test)]
                eprintln!("DEBUG i={} name_off={} shndx={} value={:#x}", i, name_off, shndx, value);
                if name_off == 0 || name_off >= strtab_size {
                    continue;
                }
                let name = read_cstr(data, strtab_base + name_off);
                if name.is_empty() {
                    continue;
                }
                // STT_SECTION 或未定义符号跳过（value 不指向映射段）
                if shndx == 0 || shndx == 0xfff1 {
                    continue;
                }
                let foff = va_to_offset(&segments, value);
                if let Some(f) = foff {
                    symbols.insert(name, f);
                }
            }
            if !symbols.is_empty() {
                break;
            }
        }
        if !symbols.is_empty() {
            break;
        }
    }

    Ok(ContainerInfo {
        symbols,
        text_vmaddr,
        cputype: Some(machine as u32),
    })
}

fn va_to_offset(segments: &[(u64, u64, u64)], va: u64) -> Option<u64> {
    for (vaddr, filesz, off) in segments {
        if *vaddr <= va && va < *vaddr + *filesz {
            return Some(*off + (va - *vaddr));
        }
    }
    None
}

fn read_cstr(data: &[u8], mut pos: usize) -> String {
    let mut end = pos;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    pos = pos.min(end);
    std::str::from_utf8(&data[pos..end]).map(|s| s.to_string()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::parse_elf;

    /// 手工构造的 64 位 ELF：1 个 PT_LOAD + 3 个节 + 2 个符号
    #[test]
    fn synthetic_elf_symbols() {
        let mut b = Vec::new();
        // ELF64 header（含 ident，直接从 0 开始）
        let mut e = vec![0u8; 64];
        e[0..4].copy_from_slice(b"\x7fELF");
        e[4] = 2; // 64-bit
        e[5] = 1; // little-endian
        e[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        e[18..20].copy_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
        e[20..24].copy_from_slice(&1u32.to_le_bytes());
        e[32..40].copy_from_slice(&64u64.to_le_bytes()); // phoff
        e[40..48].copy_from_slice(&120u64.to_le_bytes()); // shoff
        e[54..56].copy_from_slice(&56u16.to_le_bytes()); // phentsize
        e[56..58].copy_from_slice(&1u16.to_le_bytes()); // phnum
        e[58..60].copy_from_slice(&64u16.to_le_bytes()); // shentsize
        e[60..62].copy_from_slice(&3u16.to_le_bytes()); // shnum
        e[62..64].copy_from_slice(&2u16.to_le_bytes()); // shstrndx
        b.extend_from_slice(&e);
        // PT_LOAD: vaddr 0, off 0, filesz 0x1000
        let mut ph = vec![0u8; 56];
        ph[0..4].copy_from_slice(&1u32.to_le_bytes());
        ph[8..16].copy_from_slice(&0u64.to_le_bytes());
        ph[16..24].copy_from_slice(&0u64.to_le_bytes());
        ph[32..40].copy_from_slice(&0x1000u64.to_le_bytes());
        b.extend_from_slice(&ph);
        // 节区：shstr(0, SHT_STRTAB@offset 0x500), sym(1, SHT_SYMTAB@0x200, link=0), — 顺序：
        // sh0 = .shstrtab (type 3) off 0x500; sh1 = .symtab (type 2) off 0x200 link 0; sh2 = .strtab? 简化:shstrndx=2
        // 简化：sh0 dummy(type 0), sh1 symtab(2) off0x200 size48 link2 entsize24, sh2 strtab(3) off0x300 size64
        let mut shs = Vec::new();
        let mut sh0 = vec![0u8; 64];
        sh0[4..8].copy_from_slice(&0u32.to_le_bytes()); // SHT_NULL
        shs.push(sh0);
        let mut sh1 = vec![0u8; 64];
        sh1[0..4].copy_from_slice(&1u32.to_le_bytes()); // name idx（占位，shstr 在节里？我们不做名查找验证）
        sh1[4..8].copy_from_slice(&2u32.to_le_bytes()); // SHT_SYMTAB
        sh1[24..32].copy_from_slice(&0x200u64.to_le_bytes()); // offset
        sh1[32..40].copy_from_slice(&48u64.to_le_bytes()); // size
        sh1[40..44].copy_from_slice(&2u32.to_le_bytes()); // link → strtab
        sh1[56..64].copy_from_slice(&24u64.to_le_bytes()); // entsize
        shs.push(sh1);
        let mut sh2 = vec![0u8; 64];
        sh2[4..8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
        sh2[24..32].copy_from_slice(&0x300u64.to_le_bytes()); // offset
        sh2[32..40].copy_from_slice(&64u64.to_le_bytes()); // size
        shs.push(sh2);
        for s in shs {
            b.extend_from_slice(&s);
        }
        b.resize(0x200, 0);
        // symtab @0x200：2 个符号：_kDartVmSnapshotData @ va 0x100（值 1），_kDartIsolateSnapshotData @ va 0x200
        let mut sym = vec![0u8; 24];  // ELF64 Sym = 24 字节
        sym[0..4].copy_from_slice(&1u32.to_le_bytes()); // name off 1
        sym[4..5].copy_from_slice(&0x12u8.to_le_bytes()); // STB_GLOBAL|STT_FUNC 随意
        sym[6..8].copy_from_slice(&1u16.to_le_bytes()); // st_shndx = 1
        sym[8..16].copy_from_slice(&0x100u64.to_le_bytes());
        let mut sym2 = vec![0u8; 24];
        sym2[0..4].copy_from_slice(&22u32.to_le_bytes()); // 1 + len("_kDartVmSnapshotData")(20) + 1
        sym2[4..5].copy_from_slice(&0x11u8.to_le_bytes());
        sym2[6..8].copy_from_slice(&1u16.to_le_bytes()); // st_shndx = 1
        sym2[8..16].copy_from_slice(&0x200u64.to_le_bytes());
        b.extend_from_slice(&sym);
        b.extend_from_slice(&sym2);
        b.resize(0x300, 0);
        // strtab @0x300: "\0_kDartVmSnapshotData\0_kDartIsolateSnapshotData\0"
        let mut st = b"_kDartVmSnapshotData\0_kDartIsolateSnapshotData\0".to_vec();
        st.insert(0, 0);
        b.extend_from_slice(&st);

        let info = parse_elf(&b).unwrap();
        assert_eq!(info.symbols.get("_kDartVmSnapshotData"), Some(&0x100));
        assert_eq!(info.symbols.get("_kDartIsolateSnapshotData"), Some(&0x200));
        assert_eq!(info.cputype, Some(183));
        assert_eq!(info.text_vmaddr, Some(0));
    }
}