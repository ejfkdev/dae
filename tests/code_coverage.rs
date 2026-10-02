//! 覆盖率门禁：**dae 发布的每一个函数名都必须有函数体**。
//!
//! ## 为什么需要这条
//!
//! 这条不变量被破坏过**两次**，两次的产物看起来都完全正常——名字对、结构化率对、
//! `dart analyze` 零错误、`regress_all` 全绿——因为缺的不是「正确性」而是「有没有」：
//! 函数名照常进 `text/functions.txt`，而 `asm/` 与 `dart/` 里**一条也没有**。
//!
//! 两次都出在 `Analyzer::code_size`：
//!
//! | # | 缺陷 | 影响面（实测） | 为什么既有门禁全盲 |
//! |---|---|---|---|
//! | 1 | 保留了 `idx < first_entry` 旧守卫（`entry_for` 早已放行，本函数没跟着改） | Reqable **11207/13371＝83.8%**、飞书 **19921/25183＝79.1%** 的函数有名字没函数体；Reqable `asm/` 只有 999 条而函数表有 13371 行 | 26 份桌面语料与全部 25 份 regress 存档的 `first_entry_with_code` **都是 0**，守卫从不触发 |
//! | 2 | 用「下一条」而非「下一个**不同**的 offset」算长度；2.12–2.15 的 AOT 写入器会合并字节相同的 `Instructions`，连续多个表条目共享同一 `pc_offset` | hello_2.12.4 **174**、2.13.4 **217**、2.14.4 **221**、2.15.0 **212** 个函数有名字没函数体 | 只有 4 份老语料有等值 run，而它们的 `asm/` 本来就是空的（x64），`dart/` 少几百个块也看不出来 |
//!
//! 缺陷 2 的成因有独立佐证：hello_2.12.4 里 73 个地址被 2..16 个函数共享，而共享者
//! **语义上就是同一个函数体**——9 个不同 typed_data 类的 `get_elementSizeInBytes`、
//! 16 个 `_isWindows`/`_setupCompleted`/`_enableSocketProfiling` 这类布尔开关 getter、
//! 9 个错误类的 `ctor`/`get_stackTrace`。是编译器去重，不是 dae 解码错位。
//!
//! ## 判据
//!
//! 对每份语料，在进程内重建 Analyzer 并断言两件事：
//! 1. **`name_without_body == 0`**：凡 `entry_for(f.code_index)` 给出入口的 Function，
//!    `code_range(idx)` 必须也给出 (入口, 长度)。这正是被破坏的那个合取。
//! 2. **表内全覆盖**：只要语料有指令表（`pc_offsets` 非空），每个下标都必须能算出范围。
//!
//! ## 防空过：门禁自带负对照
//!
//! 「断言 0」最大的风险是**探测器根本没在测东西**（本项目已因此翻过车：解析器把空串当寄存器、
//! 把说明性注释当 gotoLabel 调用）。所以这里把两个**旧的错误公式**原样重算一遍，
//! 并断言它们在当前语料集上**确实会**报出孤儿：
//! - 旧公式 B（不去重）必须在 ≥1 份语料上报出孤儿——2.12–2.15 的等值 run 保证了这一点，
//!   也就是说**这条门禁用仓库自带语料就是敏感的**，不依赖任何外部下载。
//! - 旧公式 A（`first_entry` 守卫）只在 `first_entry > 0` 的语料上敏感。仓库内一份都没有，
//!   所以把「有几份语料 first_entry>0」如实打印出来；为 0 时明确宣告盲区，
//!   而不是让这条门禁假装覆盖了那一半。设 `DAE_TRUTH_ANDROID_SO`（逗号分隔的
//!   `libapp.so` 路径）可把真实移动端产物纳入扫描，补上这一半。
//!
//! 语料在仓库外（`dart/dart_samples/` 被 gitignore），缺失时按本仓库统一口径：
//! 默认打印跳过，`DAE_REQUIRE_GATES=1` 时直接失败。

use dae::analyzer::Analyzer;
use dae::locale::{messages, Lang};
use dae::profile::detect::detect_sdk;
use std::path::{Path, PathBuf};

fn skip_or_fail(msg: &str) {
    if std::env::var_os("DAE_REQUIRE_GATES").is_some() {
        panic!("DAE_REQUIRE_GATES=1，但门禁跳过了：{msg}");
    }
    println!("{msg}");
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// 打开一份语料。打不开（bare JIT 快照等）返回 None，由调用方计入「跳过」而不是失败——
/// `regress_all.sh` 已经把「1.24.3 / 2.0.0 应当 rc≠0」当成断言在管了。
fn load(path: &Path) -> Option<Analyzer<'static>> {
    let data: &'static [u8] = Box::leak(std::fs::read(path).ok()?.into_boxed_slice());
    let s = messages(Lang::En);
    let plat = dae::cli::resolve_platform(data, None, &s).ok()?;
    let (offs, _) = dae::platform::locate_snapshots(data, &plat).ok()?;
    let sdk = match detect_sdk(data, offs.0 as usize, offs.1 as usize) {
        Some((p, _)) => p,
        None => return None,
    };
    let plat: &'static _ = Box::leak(Box::new(plat));
    Analyzer::new_located(data, sdk, plat, offs, false).ok()
}

/// 用**给定的**长度函数数孤儿：凡 entry_for 给出入口、而该长度函数算不出可用范围的 Function。
/// `code_range` 的拒绝条件里只有 `size <= eo` 与长度有关，故这里照它复刻。
fn orphans_with<F: Fn(usize) -> u64>(a: &Analyzer, size_of: F) -> usize {
    let n = a.pc_offsets.len();
    let mut bad = 0usize;
    for f in a.iso.functions.values() {
        let Some((_ep, idx)) = a.entry_for(f.code_index) else { continue };
        if idx >= n {
            bad += 1;
            continue;
        }
        let eo = a.entry_offset(idx);
        if size_of(idx) <= eo {
            bad += 1;
        }
    }
    bad
}

#[test]
fn every_published_function_has_a_body() {
    let r = root();
    let arts = r.join("dart/dart_samples/artifacts");
    if !arts.is_dir() {
        skip_or_fail("code_coverage: 没有 dart/dart_samples/artifacts 语料——跳过");
        return;
    }

    let mut corpus: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&arts) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_file() {
                corpus.push(p);
            }
        }
    }
    corpus.sort();
    // 可选：真实移动端产物（`first_entry > 0` 那一半缺陷只有它们能触发）
    let optin = std::env::var("DAE_TRUTH_ANDROID_SO").unwrap_or_default();
    for p in optin.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        corpus.push(PathBuf::from(p));
    }

    // 旧公式 A：`idx < first_entry` 一律 0（缺陷 1）
    // 旧公式 B：只减「下一条」，不跳过等值 run（缺陷 2）
    let (mut measured, mut skipped) = (0usize, 0usize);
    let (mut tot_entries, mut tot_orphans, mut tot_fns) = (0usize, 0usize, 0usize);
    let (mut sens_a, mut sens_b) = (0usize, 0usize);
    let (mut n_fe_pos, mut n_dedup) = (0usize, 0usize);
    let mut rows: Vec<String> = Vec::new();

    for p in &corpus {
        let Some(a) = load(p) else { skipped += 1; continue };
        measured += 1;
        let n = a.pc_offsets.len();
        let label = p
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| p.display().to_string());

        // --- 判据 1：已发布名字必须有函数体 ---
        let orphan = orphans_with(&a, |i| a.code_size(i));
        // --- 判据 2：有指令表就必须逐条可算范围 ---
        let cov = (0..n).filter(|&i| a.code_range(i).is_some()).count();

        let mut pubfn = 0usize;
        for f in a.iso.functions.values() {
            if a.entry_for(f.code_index).is_some() {
                pubfn += 1;
            }
        }
        tot_entries += n;
        tot_orphans += orphan;
        tot_fns += pubfn;

        // --- 负对照：把两个旧公式各自单独装回去，看它们在这份语料上报不报孤儿 ---
        //
        // ⚠️ 两个公式必须**各自只含一个缺陷**，否则归因会串：
        // 「first_entry 守卫 + 只减下一条」在 first_entry==0 的语料上会退化成后者，
        // 于是缺陷 1 的敏感度被缺陷 2 的语料冒充（本门禁第一版就是这么写错的，
        // 报出「旧A 在 4 份上敏感」而实际那 4 份的 first_entry 全是 0）。
        let fe = a.first_entry as usize;
        // 旧 A：只装回 first_entry 守卫，长度仍用现在的（正确的）去重公式
        let next_distinct = |i: usize| -> u64 {
            if i >= n {
                return 0;
            }
            let j = a.pc_offsets.partition_point(|&x| x <= a.pc_offsets[i]);
            if j < n { a.pc_offsets[j] - a.pc_offsets[i] } else { 0x200 }
        };
        let oa = orphans_with(&a, |i| if i < fe { 0 } else { next_distinct(i) });
        // 旧 B：只装回「减下一条」，不带 first_entry 守卫
        let ob = orphans_with(&a, |i| {
            if i >= n {
                0
            } else if i + 1 < n {
                a.pc_offsets[i + 1].saturating_sub(a.pc_offsets[i])
            } else {
                0x200
            }
        });
        if fe > 0 {
            n_fe_pos += 1;
        }
        if oa > 0 {
            sens_a += 1;
        }
        if ob > 0 {
            sens_b += 1;
            n_dedup += 1;
        }

        rows.push(format!(
            "{label:34} 表 {n:6} 覆盖 {cov:6} 函数 {pubfn:6} 孤儿 {orphan:5} | first_entry {fe:6} 旧A报 {oa:5}  旧B报 {ob:5}"
        ));

        assert_eq!(
            orphan, 0,
            "{label}: {orphan} 个已发布函数名没有函数体（entry_for 给出入口而 code_range 给不出范围）。\n\
             这就是历史上两次「名字齐全而 asm//dart/ 空掉」的缺陷指纹；\n\
             查 Analyzer::code_size 的两条注释（first_entry 守卫 / Instructions 去重）。"
        );
        if n > 0 {
            assert_eq!(
                cov, n,
                "{label}: 指令表 {n} 条里只有 {cov} 条能算出 (入口, 长度)——\n\
                 差值应当为 0（24 份桌面语料 + Reqable + 飞书实测均为满覆盖）。"
            );
        }
    }

    for r in &rows {
        println!("{r}");
    }
    if measured == 0 {
        skip_or_fail("code_coverage: 语料一份都打不开——跳过");
        return;
    }
    println!(
        "合计 {measured} 份语料（打不开 {skipped} 份）：指令表 {tot_entries} 条、\
         已发布函数 {tot_fns} 个、有名字没函数体 {tot_orphans} 个"
    );

    // --- 防空过：门禁必须证明自己对缺陷敏感，否则「0 孤儿」可能只是没测到 ---
    assert!(
        measured >= 10,
        "只量到 {measured} 份语料（期望 ≥10）——语料集是不是没挂上？\n\
         少于这个数时下面的负对照也不足以证明门禁敏感。"
    );
    assert_eq!(
        sens_b, n_dedup,
        "内部不一致：sens_b={sens_b} 而 n_dedup={n_dedup}（两者都由旧公式 B 的孤儿数驱动）"
    );
    assert!(
        sens_b >= 1,
        "负对照失效：把 code_size 换回「只减下一条」的旧公式，在 {measured} 份语料上\n\
         一个孤儿都报不出来——说明当前语料集里没有等值 pc_offset run，\n\
         这条门禁对缺陷 2 是空过的。hello_2.12.4/2.13.4/2.14.4/2.15.0 应当各报 174/217/221/212。"
    );
    println!(
        "负对照：旧公式 B（不去重）在 {sens_b}/{measured} 份语料上敏感 ✓（这条门禁不空过）；\
         旧公式 A（first_entry 守卫）在 {sens_a}/{measured} 份上敏感，\
         first_entry>0 的语料 {n_fe_pos} 份"
    );
    if n_fe_pos == 0 {
        println!(
            "⚠️ 盲区（如实记录，不假装覆盖）：{measured} 份语料的 first_entry_with_code 全是 0，\n\
              所以「idx < first_entry 守卫」那一半缺陷本门禁测不到。\n\
              已知触发它的真实产物：Reqable（first_entry=48455，83.8% 函数受影响）、\n\
              飞书 lark-android（first_entry=61609，79.1%）。本机现编的 Flutter Android\n\
              arm64 产物 first_entry 也是 0，故无法用工具链合成该语料。\n\
              设 DAE_TRUTH_ANDROID_SO=/path/to/libapp.so[,/path2...] 可把它们纳入扫描。"
        );
    }
    if !optin.is_empty() && n_fe_pos == 0 {
        println!(
            "⚠️ 设了 DAE_TRUTH_ANDROID_SO 但提供的产物 first_entry 全为 0（{n_dedup} 份有等值 run）——\n\
              这一半缺陷仍未被覆盖，换一份大型真实应用的 libapp.so 再试。"
        );
    }
}
