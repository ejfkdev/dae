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

/// 健康度下限：解析**塌陷**（`libraries=1 / classes=1` 那种）会让恢复出的函数数掉一个
/// 数量级，而 dae 自己 `warnings=0`——静默劣化，正是本仓库反复吃亏的形态。
/// hello 系列健康样本是 1282–1447 个函数，塌陷时是 63 个，400 这个下限把两者干净分开。
const FUNC_FLOOR: usize = 400;

/// 已知塌陷且原因未定位的样本。登记在这里是为了**不让它掩盖新的塌陷**，
/// 而不是承认它正常。
///
/// - `hello_2.18.1`：Function 的 fill 尾部按源码判定应与 2.19.6 逐字相同
///   （`WriteFill` 两版 diff 为空、`UntaggedFunction` 字段范围相同、都是 product 构建），
///   即 refs(4) + code_index + kind_tag = **1 个 svarint**；2.15–2.17 才是 2 个
///   （那三版的 `packed_fields_` 写在 `kind != kFullAOT` 条件块**之外**）。
///   1-svarint 让 2.19.6 从 630 → 1318 个函数、并让真机微博 2.19.6 解析出与 aotopsy
///   完全相同的 22 623 个表项；但同一布局下 2.18.1 会塌陷。旧布局（2 svarint）下
///   2.18.1 也只有 `classes=2`（健康值约 320），**本来就是坏的**——多出的那个 svarint
///   只是在补偿另一处尚未定位的布局错误。
const KNOWN_COLLAPSED: &[&str] = &["hello_2.18.1"];

/// 语料：路径 + SDK/平台 profile（与 scripts/regress_all.sh 的样本表一致）
/// 门禁跳过点统一走这里：默认打印并跳过，但 `DAE_REQUIRE_GATES=1` 时**直接失败**。
///
/// 理由：`cargo test` 默认吞掉 println，而本仓库 6 个测试文件里有 5 个依赖被 gitignore 的语料
/// （`testing/`、`dart/dart_samples/`），缺语料就静默跳过——新克隆里跑 `cargo test` 会得到
/// 「全绿但几乎什么都没量」。维护者在自己的检出里设这个变量，任何本该执行却跳过的门禁都会炸出来。
/// 注意：显式 opt-in（如未设 `DAE_TRUTH_ANDROID`）不属于「缺依赖」，不走这里。
fn skip_or_fail(msg: &str) {
    if std::env::var_os("DAE_REQUIRE_GATES").is_some() {
        panic!("DAE_REQUIRE_GATES=1，但门禁跳过了：{msg}");
    }
    println!("{msg}");
}

fn corpus() -> Vec<(&'static str, PathBuf, &'static str, &'static str)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    vec![
        ("T4_blank", root.join("testing/variants/T4_blank/libapp.so"), "dart-2.12.4-w64-no-compressed.json", "elf-x64.json"),
        ("hello_2.15.0", root.join("dart/dart_samples/artifacts/hello_2.15.0.aot"), "dart-2.15.0-w64-no-compressed.json", "elf-x64.json"),
        ("hello_2.16.2", root.join("dart/dart_samples/artifacts/hello_2.16.2.aot"), "dart-2.16.2-w64-no-compressed.json", "elf-x64.json"),
        // 以下四个样本都自带 .symtab，是「2.15–3.0 的 fill 布局逐版核源码」这批改动的
        // 独立真值——regress 存档由 dae 自己产出，无法裁决自身对错；符号表可以。
        ("hello_2.18.1", root.join("dart/dart_samples/artifacts/hello_2.18.1.aot"), "dart-2.18.1-w64-no-compressed.json", "elf-x64.json"),
        ("hello_2.19.6", root.join("dart/dart_samples/artifacts/hello_2.19.6.aot"), "dart-2.19.6-w64-no-compressed.json", "elf-x64.json"),
        ("hello_3.0.0", root.join("dart/dart_samples/artifacts/hello_3.0.0.aot"), "dart-3.0.0-w64-no-compressed.json", "elf-x64.json"),
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

/// 分配 stub 命名对拍：ELF 里 `Precompiled_AllocationStub_<Class>_<n>` 这一类符号，
/// dae 应当能从 stub 序言解出同一个类名。
///
/// 硬门禁是**零编造**：命名出来的必须与真值一致，猜错一个就失败（这是"不知道就留空"
/// 的底线）。覆盖率单独打印——某些版本（2.16.x）类表层本身还没解析出来，命名率会是 0，
/// 那是另一处已知缺口，不该被这条门禁掩盖，也不该让它把"不猜"这条判据带偏。
#[cfg(feature = "asm")]
#[test]
fn alloc_stub_naming() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (mut total, mut named, mut right) = (0usize, 0usize, 0usize);
    for (label, so, sdk_name, plat_name) in corpus() {
        if !so.exists() {
            continue;
        }
        let data = std::fs::read(&so).expect("读样本");
        let syms = elf_func_symbols(&data);
        if syms.is_empty() {
            continue;
        }
        let sdk_src = std::fs::read_to_string(root.join("profiles/sdk").join(sdk_name)).unwrap();
        let plat_src = std::fs::read_to_string(root.join("profiles/platform").join(plat_name)).unwrap();
        let sdk: SdkProfile = parse_sdk(&sdk_src).unwrap();
        let plat: PlatformProfile = parse_platform(&plat_src).unwrap();
        let (vm_off, iso_off, instr_off) = dae::platform::locate_snapshots(&data, &plat).unwrap().0;
        let a = Analyzer::new_located(&data, &sdk, &plat, (vm_off, iso_off, instr_off), false).unwrap();

        // 真值：所有 AllocationStub_<Class>_<n> 的地址 → 类名
        let mut truth: Vec<(u64, String)> = Vec::new();
        for (va, sym) in &syms {
            let Some(rest) = sym.strip_prefix("Precompiled_AllocationStub_") else {
                continue;
            };
            let mut cls = rest.trim_end_matches(|c: char| c.is_ascii_digit() || c == '_');
            if let Some(i) = cls.rfind('_') {
                if cls[i + 1..].chars().all(|c| c.is_ascii_digit()) {
                    cls = &cls[..i];
                }
            }
            truth.push((*va, cls.to_string()));
        }
        if truth.is_empty() {
            continue;
        }
        let addrs: Vec<u64> = truth.iter().map(|(a, _)| *a).collect();
        let got = dae::export::callgraph::alloc_stubs_at(&a, &addrs);
        let (mut n, mut nm, mut r) = (0usize, 0usize, 0usize);
        for ((_, want), (_, have)) in truth.iter().zip(got.iter()) {
            n += 1;
            let Some(name) = have else { continue };
            nm += 1;
            let cls = name.strip_prefix("AllocationStub_").unwrap_or(name);
            if cls.contains(want.as_str()) {
                r += 1;
            }
        }
        total += n;
        named += nm;
        right += r;
        println!("{label:16} 分配 stub 真值 {n:4}  命名 {nm:4}  类名一致 {r:4}");
    }
    if total == 0 {
        skip_or_fail("alloc_stub_naming: 无语料——跳过");
        return;
    }
    println!(
        "== 分配 stub 命名: {right}/{named} 已命名的与 .symtab 一致（覆盖率 {named}/{total}）"
    );
    assert_eq!(
        named, right,
        "分配 stub 命名出现 {} 个与真值不符的名字——不许猜",
        named - right
    );
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
        if !KNOWN_COLLAPSED.contains(&label) {
            assert!(
                funcs >= FUNC_FLOOR,
                "{label}: 只恢复出 {funcs} 个函数（下限 {FUNC_FLOOR}）——解析很可能已塌陷\
                 （libraries/classes 会同时塌成 1）而 dae 不报警；\
                 若这是新的已知塌陷，必须写进 KNOWN_COLLAPSED 并附源码级原因"
            );
        } else {
            println!("{label:16} ⚠ 已登记为塌陷样本（funcs={funcs} < {FUNC_FLOOR}），原因见 KNOWN_COLLAPSED 注释");
        }
        total_cmp += cmp;
        total_agree += agree;
        total_addr_hit += hit;
        total_funcs += funcs;
        ran.push(label);
    }

    if ran.is_empty() {
        skip_or_fail("ground_truth: 无语料（dart/dart_samples 与 testing/variants 均缺失）——跳过");
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