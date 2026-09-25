//! `.symtab` 真值差分门禁：把 dae 还原的函数名/地址与二进制自带符号表对拍。
//!
//! 这是 dae 唯一的外部真值（其余回归都是与自己的旧产物比，只证"没变"、不证"对"）。
//! 语料在 gitignore 的工作区里（`dart/dart_samples/artifacts/`、`testing/variants/`），
//! 缺失时整体跳过；**存在但读不到符号**则视为失败（"语料漂了"与"没有语料"含义不同）。
//!
//! 判据沿用 aotopsy METHODOLOGY 的口径：
//! - 地址：按 VA 精确匹配（还原入口 == 符号地址）；
//! - 名称：双方归一化后比较（丢掉各自的方言差异），诚实分母（Unnamed 不计）。
//!
//! 门禁下限取 0.80（aotopsy 的门是 0.81；dae 当前在本机语料上高于它）。

use dae::analyzer::Analyzer;
use dae::profile::{parse_platform, parse_sdk, PlatformProfile, SdkProfile};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const NAME_FLOOR: f64 = 0.80;

/// 语料：路径 + SDK/平台 profile（与 scripts/regress_all.sh 的样本表一致）
fn corpus() -> Vec<(&'static str, PathBuf, &'static str, &'static str)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    vec![
        ("T4_blank", root.join("testing/variants/T4_blank/libapp.so"), "dart-2.12.4-w64-no-compressed.json", "elf-x64.json"),
        ("hello_2.15.0", root.join("dart/dart_samples/artifacts/hello_2.15.0.aot"), "dart-2.15.0-w64-no-compressed.json", "elf-x64.json"),
        ("hello_2.16.2", root.join("dart/dart_samples/artifacts/hello_2.16.2.aot"), "dart-2.16.2-w64-no-compressed.json", "elf-x64.json"),
    ]
}

/// 读 ELF `.symtab` 的函数符号（name, addr）。非 ELF / 无符号 → 空表。
fn elf_func_symbols(data: &[u8]) -> BTreeMap<u64, String> {
    let mut out = BTreeMap::new();
    if data.len() < 64 || &data[..4] != b"\x7fELF" || data[4] != 2 {
        return out;
    }
    let u16at = |o: usize| u16::from_le_bytes([data[o], data[o + 1]]) as usize;
    let u32at = |o: usize| u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]) as usize;
    let u64at = |o: usize| {
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[o..o + 8]);
        u64::from_le_bytes(b)
    };
    let shoff = u64at(0x28) as usize;
    let shentsize = u16at(0x3a);
    let shnum = u16at(0x3c);
    let (mut sym_off, mut sym_num, mut sym_entsz, mut str_off, mut str_sz) = (0usize, 0usize, 0usize, 0usize, 0usize);
    let mut found_stab = false;
    for i in 0..shnum {
        let o = shoff + i * shentsize;
        if o + 0x28 > data.len() {
            break;
        }
        let sh_type = u32at(o + 4);
        if sh_type == 2 {
            // SHT_SYMTAB
            sym_off = u64at(o + 0x18) as usize;
            sym_num = (u64at(o + 0x20) as usize) / 24;
            sym_entsz = 24;
            let link = u32at(o + 0x28) as usize; // sh_link
            let lo = shoff + link * shentsize;
            str_off = u64at(lo + 0x18) as usize;
            str_sz = u64at(lo + 0x20) as usize;
            found_stab = true;
            break;
        }
    }
    if !found_stab {
        return out;
    }
    for i in 0..sym_num {
        let o = sym_off + i * sym_entsz;
        if o + 24 > data.len() {
            break;
        }
        let st_name = u32at(o) as usize;
        let st_info = data[o + 4];
        let st_shndx = u16at(o + 6);
        let st_value = u64at(o + 8);
        // 只要代码类符号：FUNC 或 NOTYPE（链接器对部分 Dart 符号用 NOTYPE）
        let ty = st_info & 0x0f;
        if ty != 2 && ty != 0 {
            continue;
        }
        if st_shndx == 0 || st_name == 0 || str_off + st_name >= data.len() || st_name >= str_sz {
            continue;
        }
        let s = &data[str_off + st_name..];
        let end = s.iter().position(|&b| b == 0).unwrap_or(0);
        let name = String::from_utf8_lossy(&s[..end]).into_owned();
        if !name.is_empty() {
            out.insert(st_value, name);
        }
    }
    out
}

fn norm_tokens(s: &str) -> Vec<String> {
    let mut t = s.to_lowercase();
    t = t.replace("precompiled_", "");
    // 去掉结尾的 _<十进制序号>（2.x 汇编方言的 code_index）
    if let Some(i) = t.rfind('_') {
        if i + 1 < t.len() && t[i + 1..].chars().all(|c| c.is_ascii_digit()) {
            t.truncate(i);
        }
    }
    let mapped: String = t
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    mapped
        .split('_')
        .filter(|x| !x.is_empty())
        .map(|x| x.to_string())
        .collect()
}

/// dae 的成员方言 → 符号表里可能的写法（每组都必须在 ELF token 里能找到）
fn dae_member_variants(mangled: &str, cls: &str) -> Vec<Vec<String>> {
    let m = mangled.to_lowercase();
    let mut raw: Vec<String> = Vec::new();
    let mut v: Option<String> = None;
    if m == "ctor" {
        raw.push(cls.to_lowercase());
    } else if let Some(rest) = m.strip_prefix("factory_ctor_") {
        v = Some(rest.to_string());
    } else if let Some(rest) = m.strip_prefix("ctor_") {
        v = Some(rest.to_string());
    } else if let Some(rest) = m.strip_prefix("get_") {
        v = Some(rest.trim_start_matches('_').to_string());
    } else if let Some(rest) = m.strip_prefix("set_") {
        v = Some(rest.trim_start_matches('_').to_string());
    } else if let Some(rest) = m.strip_prefix("dyn_") {
        v = Some(rest.trim_start_matches('_').to_string());
    } else if let Some(rest) = m.strip_suffix("_assign") {
        v = Some(rest.to_string());
    } else if m == "_anon_closure" {
        raw.push("anonymous".into());
        raw.push("closure".into());
    } else if m.starts_with("op_") {
        // 2.x 汇编方言把运算符整体折成下划线（`[]` → `__`），无法按名匹配——
        // 记为"不可比"而不是不一致（aotopsy 同样处理）。
        return Vec::new();
    } else {
        v = Some(m.trim_start_matches('_').to_string());
    }
    if let Some(x) = v {
        raw.extend(norm_tokens(&x));
    }
    if raw.is_empty() {
        return Vec::new();
    }
    // 两条独立判据：成员 token 全含；成员 + 类名 token 全含
    let mut with_cls = raw.clone();
    if !cls.is_empty() {
        with_cls.extend(norm_tokens(cls));
    }
    vec![raw, with_cls]
}

fn tokens_contain(hay: &[String], needle: &[String]) -> bool {
    needle.iter().all(|n| {
        n.is_empty() || hay.iter().any(|h| h == n || h.contains(n.as_str()))
    })
}

#[test]
fn symtab_differential() {
    let mut total_cmp = 0usize;
    let mut total_agree = 0usize;
    let mut total_addr_hit = 0usize;
    let mut total_funcs = 0usize;
    let mut ran = Vec::new();

    for (label, so, sdk_name, plat_name) in corpus() {
        if !so.exists() {
            continue; // 语料缺失 → 跳过（不入库）
        }
        let data = std::fs::read(&so).expect("读样本");
        let syms = elf_func_symbols(&data);
        assert!(
            !syms.is_empty(),
            "{label}: 语料存在但没有可用符号表——语料漂了，不是缺语料"
        );

        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let sdk_src = std::fs::read_to_string(root.join("profiles/sdk").join(sdk_name)).unwrap();
        let plat_src = std::fs::read_to_string(root.join("profiles/platform").join(plat_name)).unwrap();
        let sdk: SdkProfile = parse_sdk(&sdk_src).unwrap();
        let plat: PlatformProfile = parse_platform(&plat_src).unwrap();

        let (vm_off, iso_off, instr_off) = dae::platform::locate_snapshots(&data, &plat)
            .expect("定位快照")
            .0;
        let a = Analyzer::new_located(&data, &sdk, &plat, (vm_off, iso_off, instr_off), false)
            .expect("解析快照");

        let libs = a.build_functions(true);
        let mut cmp = 0usize;
        let mut agree = 0usize;
        let mut hit = 0usize;
        let mut funcs = 0usize;
        for (_, cls_map) in &libs {
            for (cls, fs) in cls_map {
                for f in fs {
                    if f.ep == 0 {
                        continue;
                    }
                    funcs += 1;
                    let Some(sym) = syms.get(&f.ep) else { continue };
                    hit += 1;
                    let variants = dae_member_variants(&f.mangled, cls);
                    if variants.is_empty() {
                        continue; // 不可比（2.x 运算符等）：诚实分母，不计入一致率
                    }
                    cmp += 1;
                    let hay = norm_tokens(sym);
                    if variants.into_iter().any(|v| tokens_contain(&hay, &v)) {
                        agree += 1;
                    }
                }
            }
        }
        let rate = if cmp == 0 { 0.0 } else { agree as f64 / cmp as f64 };
        println!(
            "{label:16} 符号表 {:5}  函数 {funcs:5}  地址命中符号表 {hit:5}  名称可比 {cmp:5}  一致 {agree:5} → {:.1}%",
            syms.len(),
            rate * 100.0
        );
        total_cmp += cmp;
        total_agree += agree;
        total_addr_hit += hit;
        total_funcs += funcs;
        ran.push(label);
    }

    if ran.is_empty() {
        println!("ground_truth: 无语料（dart/dart_samples 与 testing/variants 均缺失）——跳过");
        return;
    }
    let rate = total_agree as f64 / total_cmp as f64;
    println!(
        "== 合计（{} 个样本）: 地址命中 {}/{} ({:.1}%)，名称一致 {}/{} ({:.1}%)，门禁 ≥ {:.2}",
        ran.len(),
        total_addr_hit,
        total_funcs,
        total_addr_hit as f64 / total_funcs as f64 * 100.0,
        total_agree,
        total_cmp,
        rate * 100.0,
        NAME_FLOOR
    );
    // 地址层：有符号可比的函数必须 100% 命中（bare-instructions 地址基址回归门）
    assert_eq!(
        total_addr_hit, total_funcs,
        "地址层：还有函数入口没落在符号表地址上"
    );
    assert!(
        rate >= NAME_FLOOR,
        "名称一致率 {:.3} 低于门禁 {:.2}",
        rate,
        NAME_FLOOR
    );
}