//! 跨语料的 **stub 命名编造扫描**：把 dae 发出的每一个 stub 名字都反推回
//! 「该语料自己的 SDK 版本 + 架构 + 压缩与否」对应的 `DartThread` 布局与类表，
//! 对不上就算一处可疑。
//!
//! ## 为什么需要一条「扫全部语料」的门禁
//!
//! 现有的命名门禁各自只吃 1–3 份语料：
//! * `ground_truth.rs::alloc_stub_naming` —— 6 份，**全是 x64**（`elf-x64.json`）；
//! * `cli_query.rs::write_barrier_stub_names_are_provable` —— 1 份 arm64；
//! * `cli_query.rs::code_reg_stub_names_trace_back_to_profile_and_instructions` —— 1 份 arm64；
//! * `cli_query.rs::inline_alloc_stub_names_match_the_class_table` —— 1 份 arm64。
//!
//! 而命名逻辑里有**三处随版本/构建方式变化**的输入：SDK 版本（决定 `DartThread` 布局）、
//! 架构（arm64 与 x64 是两套寄存器与两套物化形态）、以及**压缩指针**
//! （`heap_base` 是 `thread.h` 里唯一的 `DART_COMPRESSED_POINTERS` 条件字段，
//! 压缩构建里它之后的每个字段都晚 8 字节）。只测一两份语料时，**恰好选到对的语料就会全绿**——
//! 本次会话真发生过：`ArrayWriteBarrierStub_*` 这个错名在 material_3_demo（非压缩）与
//! weibo（2.19.6 的结构头本就含 `heap_base`）上都验得过，只在 Reqable/飞书上才是错的。
//!
//! ## 判据（每条都在**该语料自己的** profile 上重算，不写死任何版本）
//!
//! 1. 名字形状必须落在已知四类之一：`AllocationStub_<Class>`、`WriteBarrierStub_x<N>`、
//!    `<Camel>Stub_0x<addr>`、`RuntimeCallStub_0x<addr>`；
//! 2. 名字里**零非 ASCII**（仓库口径：导出物一律英文）；
//! 3. `<Camel>Stub_0x<addr>` 的地址必须等于**本行自己的**入口地址；
//! 4. `<Camel>Stub` 的词干必须能在该语料 `dart_struct-<arch>.h` 的某个 `*_stub` 字段上
//!    CamelCase 出来——**压缩指针目标要先按 `heap_base` 规则补一个字段再查**，
//!    否则会整段错位 8 字节（正是上面那个错名的成因）；
//! 5. `text/call_edges.txt` 与 `text/stubs.txt` 对同一地址必须给出**同一个名字**
//!    （两条命名路径曾经分叉过：`name_alloc_stubs` 只调 `alloc_stub_name`）。
//!
//! ## 成本与运行方式
//!
//! 要把每份语料全量导出一遍，所以 `#[ignore]`，与 `dart_valid::full_scorecard` 同级：
//! 发版前跑 `cargo test --release --test stub_names -- --ignored --nocapture`。
//! 语料在仓库外（`dart/dart_samples/`、`/tmp` 里的 APK 提取物），缺失时按本仓库口径处理：
//! 默认打印跳过，`DAE_REQUIRE_GATES=1` 时直接失败。真实移动端产物用
//! `DAE_TRUTH_ANDROID_SO=a.so,b.so` 追加——**这一条不是可选的锦上添花**：
//! 压缩指针那一半判据只有它们能触发。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

fn skip_or_fail(msg: &str) {
    if std::env::var_os("DAE_REQUIRE_GATES").is_some() {
        panic!("DAE_REQUIRE_GATES=1，但门禁跳过了：{msg}");
    }
    println!("{msg}");
}

fn run(bin: &str, args: &[&str]) -> (String, String, i32) {
    let out = Command::new(bin).args(args).output().expect("启动 dae 失败");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.code().unwrap_or(-1),
    )
}

fn camel(snake: &str) -> String {
    let mut o = String::with_capacity(snake.len());
    let mut up = true;
    for c in snake.chars() {
        if c == '_' {
            up = true;
        } else if up {
            o.extend(c.to_uppercase());
            up = false;
        } else {
            o.push(c);
        }
    }
    o
}

/// 解析 `dart_struct-<arch>.h` 的字段序列；`compressed` 时按 SDK `thread.h` 的规则
/// 在 `write_barrier_mask` 之后补 `heap_base`（已含则幂等）。
fn thread_fields(root: &Path, sdk: &str, arch: &str, compressed: bool) -> Option<Vec<String>> {
    let p = root
        .join("profiles/struct")
        .join(sdk.replace('/', "-"))
        .join(format!("dart_struct-{arch}.h"));
    let txt = std::fs::read_to_string(&p).ok()?;
    let mut f: Vec<String> = txt
        .lines()
        .skip(1)
        .take_while(|l| !l.trim_start().starts_with('}'))
        .filter_map(|l| l.trim().trim_end_matches(';').split_whitespace().last().map(String::from))
        .collect();
    if f.len() < 100 {
        return None; // 解析器没生效，别拿它当判据
    }
    if compressed && !f.iter().any(|x| x == "heap_base") {
        if let Some(i) = f.iter().position(|x| x == "write_barrier_mask") {
            f.insert(i + 1, "heap_base".to_string());
        }
    }
    Some(f)
}

#[test]
#[ignore = "要把每份语料全量导出一遍（发版前跑：--ignored --nocapture）"]
fn stub_names_are_provable_across_every_corpus() {
    let bin = env!("CARGO_BIN_EXE_dae");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let arts = root.join("dart/dart_samples/artifacts");

    let mut corpus: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&arts) {
        for e in rd.flatten() {
            let p = e.path();
            let skip = p
                .extension()
                .map(|x| matches!(x.to_str(), Some("i64") | Some("md") | Some("dill") | Some("jit")))
                .unwrap_or(false);
            if p.is_file() && !skip {
                corpus.push(p);
            }
        }
    }
    corpus.sort();
    for p in std::env::var("DAE_TRUTH_ANDROID_SO")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let pb = PathBuf::from(p);
        if pb.exists() {
            corpus.push(pb);
        } else {
            println!("  (DAE_TRUTH_ANDROID_SO 路径不存在，跳过: {p})");
        }
    }
    if corpus.is_empty() {
        skip_or_fail("stub_names: 一份语料都没有（dart/dart_samples/artifacts 缺失）——跳过");
        return;
    }

    let work = root.join("target").join("stub_names_sweep");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();

    let shape_ok = |n: &str| -> bool {
        n.starts_with("AllocationStub_")
            || n.starts_with("RuntimeCallStub_0x")
            || n.strip_prefix("WriteBarrierStub_x")
                .map(|d| !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()))
                .unwrap_or(false)
            || {
                // <Camel>Stub_0x<addr>
                match n.rsplit_once("Stub_0x") {
                    Some((stem, addr)) => {
                        !stem.is_empty()
                            && stem.starts_with(|c: char| c.is_ascii_uppercase())
                            && !addr.is_empty()
                            && addr.chars().all(|c| c.is_ascii_hexdigit())
                    }
                    None => false,
                }
            }
    };

    let (mut n_corpus, mut n_names, mut n_arm64, mut n_compressed) = (0usize, 0usize, 0usize, 0usize);
    let mut bad: Vec<String> = Vec::new();
    let mut per_family: BTreeMap<String, usize> = BTreeMap::new();

    for (i, b) in corpus.iter().enumerate() {
        let label = b.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        let out = work.join(format!("c{i}"));
        let os = out.to_string_lossy().to_string();
        let bs = b.to_string_lossy().to_string();
        let (_so, _se, rc) = run(bin, &[&bs, &os]);
        if rc != 0 {
            println!("{label:44} 打不开（rc={rc}），不计入");
            continue;
        }
        // 该语料选了哪个 SDK / 架构 / 是否压缩指针
        let (info, _e, irc) = run(bin, &["info", &bs]);
        assert_eq!(irc, 0, "{label}: info 失败");
        let (mut sdk, mut arch, mut feats) = (String::new(), String::new(), String::new());
        for ln in info.lines() {
            let c: Vec<&str> = ln.split('\t').collect();
            if c.len() >= 2 {
                match c[0] {
                    "sdk" => sdk = c[1].trim().to_string(),
                    "arch" => arch = c[1].trim().to_string(),
                    "features" => feats = c[1].trim().to_string(),
                    _ => {}
                }
            }
        }
        // features 串里 `no-compressed-pointers` 与 `compressed-pointers` 都可能出现，先判否
        let compressed = feats.contains("compressed-pointers") && !feats.contains("no-compressed-pointers");
        if arch == "arm64" {
            n_arm64 += 1;
        }
        if compressed {
            n_compressed += 1;
        }
        let fields = thread_fields(root, &sdk, &arch, compressed);
        let stub_camels: BTreeSet<String> = fields
            .as_ref()
            .map(|f| f.iter().filter(|x| x.ends_with("_stub")).map(|x| camel(x)).collect())
            .unwrap_or_default();

        let sp = out.join("text/stubs.txt");
        let Ok(stubs) = std::fs::read_to_string(&sp) else { continue };
        n_corpus += 1;
        let mut addr2name: BTreeMap<String, String> = BTreeMap::new();
        let mut local = 0usize;
        for ln in stubs.lines() {
            let c: Vec<&str> = ln.split('\t').collect();
            if c.len() < 4 || c[3].is_empty() {
                continue;
            }
            let nm = c[3];
            local += 1;
            n_names += 1;
            let fam = if nm.starts_with("AllocationStub_") {
                "AllocationStub_<Class>"
            } else if nm.starts_with("RuntimeCallStub_0x") {
                "RuntimeCallStub_0x<addr>"
            } else if nm.starts_with("WriteBarrierStub_x") {
                "WriteBarrierStub_x<N>"
            } else {
                "<Camel>Stub_0x<addr>"
            };
            *per_family.entry(fam.to_string()).or_insert(0) += 1;

            if !nm.is_ascii() {
                bad.push(format!("{label}: 名字含非 ASCII: {nm}"));
            }
            if !shape_ok(nm) {
                bad.push(format!("{label}: 名字形状不在已知四类里: {nm}"));
            }
            if let Some((stem, addr)) = nm.rsplit_once("Stub_0x") {
                if stem != "RuntimeCall" {
                    if addr != c[0].trim_start_matches("0x").to_ascii_lowercase() {
                        bad.push(format!(
                            "{label}: {nm} 名字里的地址与本行入口 {} 不符",
                            c[0]
                        ));
                    }
                    if !stub_camels.is_empty() && !stub_camels.contains(&format!("{stem}Stub")) {
                        bad.push(format!(
                            "{label}: {nm} 的词干 {stem}Stub 不在 {sdk}/{arch}{} 的 *_stub 字段里",
                            if compressed { "（压缩指针，已补 heap_base）" } else { "" }
                        ));
                    }
                }
            }
            addr2name.insert(c[0].to_string(), nm.to_string());
        }
        // call_edges 与 stubs 对同一地址必须同名
        let mut mism = 0usize;
        if let Ok(edges) = std::fs::read_to_string(out.join("text/call_edges.txt")) {
            for ln in edges.lines() {
                let c: Vec<&str> = ln.split('\t').collect();
                if c.len() >= 5 && c[2] == "direct" && !c[4].is_empty() {
                    if let Some(want) = addr2name.get(c[3]) {
                        if want != c[4] {
                            mism += 1;
                        }
                    }
                }
            }
        }
        if mism > 0 {
            bad.push(format!("{label}: call_edges.txt 与 stubs.txt 有 {mism} 处同地址不同名"));
        }
        println!(
            "{label:44} {sdk:22} {arch:6} compressed={compressed:<5} stub名={local:6} 冲突={mism}"
        );
    }

    for (k, v) in &per_family {
        println!("  家族 {k:26} {v} 个");
    }
    println!(
        "合计 {n_corpus} 份语料、{n_names} 个 stub 名字（arm64 {n_arm64} 份、压缩指针 {n_compressed} 份）"
    );

    // --- 防空过：这些数低于门槛就说明扫描根本没跑起来，「0 处可疑」毫无意义 ---
    assert!(
        n_corpus >= 15,
        "只扫到 {n_corpus} 份语料（期望 ≥15）——语料集是不是没挂上？"
    );
    // 门槛按**只用仓库自带语料**时也能过标定：24 份桌面语料实测 1 816 个名字
    // （加上 5 份真实移动端产物是 23 446）。定太高会让这条发版门禁在没有 APK 的检出里
    // 因为门槛而不是因为可疑名字失败，那是误导。
    assert!(
        n_names >= 1500,
        "只扫到 {n_names} 个 stub 名字（期望 ≥1500；24 份桌面语料实测 1816、加移动端 23446）——         命名链或 stubs.txt 解析可能没生效"
    );
    assert!(
        n_arm64 >= 3,
        "只有 {n_arm64} 份 arm64 语料（期望 ≥3）：CODE_REG / 写屏障 / 胖分配三族都只在 arm64 上生效，\
         arm64 语料太少这条门禁对它们就是空过的"
    );
    for fam in ["AllocationStub_<Class>", "<Camel>Stub_0x<addr>"] {
        assert!(
            per_family.get(fam).copied().unwrap_or(0) >= 20,
            "家族 {fam} 只扫到 {} 个（期望 ≥20）——这一族等于没测",
            per_family.get(fam).copied().unwrap_or(0)
        );
    }
    if n_compressed == 0 {
        println!(
            "⚠️ 盲区（如实记录）：本次 {n_corpus} 份语料**没有一份是压缩指针**，\n\
             所以「压缩构建要在 write_barrier_mask 之后补 heap_base」这半边判据没被触发。\n\
             设 DAE_TRUTH_ANDROID_SO 指向真实移动端 libapp.so（几乎都是压缩指针）即可补上；\n\
             这一半正是本次会话里 `ArrayWriteBarrierStub_*` 那个错名唯一能被抓住的地方。"
        );
    }

    assert!(
        bad.is_empty(),
        "stub 命名扫描发现 {} 处可疑（前 20 条）：\n{}",
        bad.len(),
        bad.iter().take(20).cloned().collect::<Vec<_>>().join("\n")
    );
    println!("stub 命名扫描: {n_names} 个名字全部可反推到该语料自己的 DartThread 布局/形状约定，0 处可疑");
    let _ = std::fs::remove_dir_all(&work);
}
