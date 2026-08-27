//! PE 容器适配器（Windows Flutter App.exe）：COFF 符号表（+ 字符串表）为主，
//! 符号表缺失时回退导出目录（IMAGE_DIRECTORY_ENTRY_EXPORT = 0）。
//! 节表做 RVA/VA → 文件偏移映射。本适配器无 Windows 样本实测，标注 unverified。

use super::ContainerInfo;
use std::collections::HashMap;

pub fn parse_pe(data: &[u8]) -> Result<ContainerInfo, String> {
    if data.len() < 64 || &data[..2] != b"MZ" {
        return Err("非 PE（无 MZ 头）".into());
    }
    let lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    if lfanew + 24 > data.len() || &data[lfanew..lfanew + 4] != b"PE\0\0" {
        return Err("PE 签名无效".into());
    }
    let coff = lfanew + 4;
    let machine = u16::from_le_bytes(data[coff..coff + 2].try_into().unwrap());
    let nsections = u16::from_le_bytes(data[coff + 2..coff + 4].try_into().unwrap()) as usize;
    let ptr_symtab = u32::from_le_bytes(data[coff + 8..coff + 12].try_into().unwrap()) as usize;
    let n_symbols = u32::from_le_bytes(data[coff + 12..coff + 16].try_into().unwrap()) as usize;
    let sz_optional = u16::from_le_bytes(data[coff + 16..coff + 18].try_into().unwrap()) as usize;
    let opt = coff + 20;
    if opt + sz_optional > data.len() {
        return Err("可选头越界".into());
    }
    let magic = u16::from_le_bytes(data[opt..opt + 2].try_into().unwrap());
    // PE32+: ImageBase u64 @opt+24；PE32: u32 @opt+28
    let image_base: u64 = if magic == 0x20B {
        u64::from_le_bytes(data[opt + 24..opt + 32].try_into().unwrap())
    } else if magic == 0x10B {
        u32::from_le_bytes(data[opt + 28..opt + 32].try_into().unwrap()) as u64
    } else {
        return Err(format!("未知 PE optional magic {magic:#x}"));
    };
    // 区段表
    struct Sect {
        rva: u32,
        vsize: u32,
        raw: u32,
    }
    let mut sections: Vec<Sect> = Vec::new();
    let sec_base = opt + sz_optional;
    for i in 0..nsections {
        let p = sec_base + i * 40;
        if p + 40 > data.len() {
            break;
        }
        sections.push(Sect {
            vsize: u32::from_le_bytes(data[p + 8..p + 12].try_into().unwrap()),
            rva: u32::from_le_bytes(data[p + 12..p + 16].try_into().unwrap()),
            raw: u32::from_le_bytes(data[p + 20..p + 24].try_into().unwrap()),
        });
    }
    let text_vmaddr = sections.first().map(|s| image_base + s.rva as u64);
    let rva_to_foff = |rva: u64| -> Option<u64> {
        for s in &sections {
            if (s.rva as u64) <= rva && rva < (s.rva as u64) + s.vsize as u64 {
                return Some(s.raw as u64 + (rva - s.rva as u64));
            }
        }
        None
    };

    // 1) COFF 符号表
    let mut symbols = HashMap::new();
    if ptr_symtab != 0 && n_symbols > 0 {
        let strtab_off = ptr_symtab + n_symbols * 18;
        let mut i = 0usize;
        while i < n_symbols {
            let p = ptr_symtab + i * 18;
            if p + 18 > data.len() {
                break;
            }
            let name = if u32::from_le_bytes(data[p..p + 4].try_into().unwrap()) == 0 {
                let noff = u32::from_le_bytes(data[p + 4..p + 8].try_into().unwrap()) as usize;
                read_cstr(data, strtab_off + noff)
            } else {
                read_cstr(data, p)
            };
            let value = u32::from_le_bytes(data[p + 8..p + 12].try_into().unwrap());
            let sec_no = u16::from_le_bytes(data[p + 12..p + 14].try_into().unwrap()) as i32;
            let n_aux = data[p + 17] as usize;
            if !name.is_empty() && sec_no > 0 && (sec_no as usize) <= sections.len() {
                let s = &sections[sec_no as usize - 1];
                let foff = s.raw as u64 + value as u64;
                if foff < data.len() as u64 {
                    symbols.entry(name).or_insert(foff);
                }
            }
            i += 1 + n_aux;
        }
    }

    // 2) 回退：导出目录（仅导出的符号）
    if symbols.is_empty() {
        let (num_dirs_at, exp_dir_at) = if magic == 0x20B { (108, 112) } else { (92, 96) };
        let num_dirs = u32::from_le_bytes(
            data[opt + num_dirs_at..opt + num_dirs_at + 4]
                .try_into()
                .unwrap(),
        );
        let export_dir_rva = if num_dirs > 0 {
            u32::from_le_bytes(data[opt + exp_dir_at..opt + exp_dir_at + 4].try_into().unwrap())
        } else {
            0
        };
        if export_dir_rva != 0 {
            if let Some(ed_off) = rva_to_foff(export_dir_rva as u64) {
                let ed = ed_off as usize;
                if ed + 40 <= data.len() {
                    let n_names =
                        u32::from_le_bytes(data[ed + 24..ed + 28].try_into().unwrap()) as usize;
                    let names_rva = u32::from_le_bytes(data[ed + 32..ed + 36].try_into().unwrap());
                    let funcs_rva = u32::from_le_bytes(data[ed + 28..ed + 32].try_into().unwrap());
                    let ords_rva = u32::from_le_bytes(data[ed + 36..ed + 40].try_into().unwrap());
                    if let (Some(names_off), Some(funcs_off), Some(ords_off)) = (
                        rva_to_foff(names_rva as u64),
                        rva_to_foff(funcs_rva as u64),
                        rva_to_foff(ords_rva as u64),
                    ) {
                        for i in 0..n_names {
                            let np = names_off as usize + i * 4;
                            let op = ords_off as usize + i * 2;
                            let fp = funcs_off as usize + i * 4;
                            if np + 4 > data.len() || op + 2 > data.len() || fp + 4 > data.len() {
                                break;
                            }
                            let name_rva =
                                u32::from_le_bytes(data[np..np + 4].try_into().unwrap());
                            let ord = u16::from_le_bytes(data[op..op + 2].try_into().unwrap()) as usize;
                            let func_rva =
                                u32::from_le_bytes(data[funcs_off as usize + ord * 4..funcs_off as usize + ord * 4 + 4].try_into().unwrap());
                            if let Some(name_off) = rva_to_foff(name_rva as u64) {
                                let name = read_cstr(data, name_off as usize);
                                if !name.is_empty() {
                                    if let Some(f) =
                                        rva_to_foff(func_rva as u64).filter(|f| *f < data.len() as u64)
                                    {
                                        symbols.entry(name).or_insert(f);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(ContainerInfo {
        symbols,
        text_vmaddr,
        cputype: Some(machine as u32),
    })
}

fn read_cstr(data: &[u8], pos: usize) -> String {
    let mut end = pos;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    if pos >= end {
        return String::new();
    }
    std::str::from_utf8(&data[pos..end]).map(|s| s.to_string()).unwrap_or_default()
}