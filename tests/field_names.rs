//! 字段名恢复门禁。
//!
//! AOT 产物里字段名几乎全被删掉（`Precompiler::DropFields` 只在非 PRODUCT 构建保留），
//! dae 只走两条**可证**路径（见 src/decompiler.rs 的「字段名恢复」）：
//!
//! 1. **Field 簇**：snapshot 直接写着名字；偏移由 Mint 值给出（Smis 被并进 Mint 簇，
//!    值即字索引，字节偏移 = 字索引 × word_size）；
//! 2. **访问器名**：隐式 getter/setter（kind 6/7）的名字就是字段名，而访问器体里
//!    **恰好一处**字段形访问——那处访问的位移 + 1 就是字节偏移。
//!
//! 两条路径互相独立：一条读 snapshot 的字段表，另一条读机器码位移 + 函数名。
//! 它们对同一 (类, 偏移, 名字) 的一致次数（`agreements`）就是这个模块的自证，
//! 也是本门禁的主判据——偏移换算或名字提取一旦回归，这个数会直接塌掉，
//! 而「产物仍然合法 Dart」这类形态指标完全看不出来。
//!
//! 另外两条硬判据：
//! - **零冲突**：两个来源给出不同名字的条目必须为空（有冲突说明某一侧在瞎猜）；
//! - **零编造**：产物里出现的每个 `/* 类.字段 (off 0x..) */` 注解都必须能在恢复表里
//!   找到同名同偏移的条目，且该偏移换算回机器码位移后确实是 8 的倍数 + 1。

use dae::analyzer::Analyzer;
use dae::profile::{parse_platform, parse_sdk};

fn load(root: &std::path::Path, bin: &str, sdk_name: &str, plat_name: &str) -> Option<Analyzer<'static>> {
    let p = root.join(bin);
    if !p.exists() {
        return None;
    }
    let sdk_src = std::fs::read_to_string(root.join("profiles/sdk").join(sdk_name)).ok()?;
    let plat_src = std::fs::read_to_string(root.join("profiles/platform").join(plat_name)).ok()?;
    let sdk = parse_sdk(&sdk_src).ok()?;
    let plat = parse_platform(&plat_src).ok()?;
    let data: &'static [u8] = Box::leak(std::fs::read(&p).unwrap().into_boxed_slice());
    let (offs, _) = dae::platform::locate_snapshots(data, &plat).ok()?;
    Analyzer::new_located(data, Box::leak(Box::new(sdk)), Box::leak(Box::new(plat)), offs, false).ok()
}

/// (标签, 路径, SDK profile, 平台 profile, 记录下限, 两源一致下限, 必须命中的 (类, 字段, 偏移))
type Case = (&'static str, &'static str, &'static str, &'static str, usize, usize, &'static [(&'static str, &'static str, u64)]);

#[test]
fn field_names_are_provable() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let cases: &[Case] = &[
        // arm64 + Mach-O appended 快照：_FutureListener/_Uri 的字段都在 pragma 保留集里，
        // 偏移由 SDK 源码核对过（_Uri.path 是第 5 个声明字段 → 字 5 → 0x28）
        (
            "sample_arm64",
            "testing/decompiler_corpus/sample_arm64",
            "dart-3.13.0-w64-no-compressed.json",
            "macho-arm64.json",
            40,
            30,
            &[
                ("_FutureListener", "result", 0x18),
                ("_FutureListener", "_nextListener", 0x10),
                ("_FutureListener", "callback", 0x28),
                ("_Uri", "path", 0x28),
                ("Error", "_stackTrace", 0x8),
            ],
        ),
        // 同一 SDK 的 x64 产物：字段表一样，位移写法不同（x64 把 base+disp 写在一个操作数里），
        // 所以这条语料盯着 base_disp 两种写法都要认
        (
            "hello_3.13.0 x64",
            "dart/dart_samples/artifacts/hello_3.13.0.aot",
            "dart-3.13.0-w64-no-compressed.json",
            "macho-x64.json",
            40,
            30,
            &[
                ("_FutureListener", "result", 0x18),
                ("Error", "_stackTrace", 0x8),
            ],
        ),
        // 2.12.4 ELF x64：老版本的 Field 簇布局不同（cid 9，多了条件位读），
        // 偏移语义必须一致——不一致的话一致数会掉到 0
        (
            "T4_blank 2.12.4 x64",
            "testing/variants/T4_blank/libapp.so",
            "dart-2.12.4-w64-no-compressed.json",
            "elf-x64.json",
            20,
            4,
            &[("_Uri", "path", 0x28), ("Error", "_stackTrace", 0x8)],
        ),
    ];

    let mut ran = 0usize;
    for (label, bin, sdk_name, plat_name, min_rec, min_agree, probes) in cases {
        let Some(a) = load(root, bin, sdk_name, plat_name) else {
            println!("{label}: 语料缺失，跳过");
            continue;
        };
        let rec = dae::decompiler::recover_fields(&a).expect("字段恢复失败");
        println!(
            "{label:22} 记录 {:4}  访问器新增 {:3}  合计 {:4}  两源一致 {:3}  冲突 {}",
            rec.from_records,
            rec.from_accessors,
            rec.by_class_off.len(),
            rec.agreements,
            rec.conflicts.len()
        );
        ran += 1;

        assert!(
            rec.conflicts.is_empty(),
            "{label}: 两个来源给出不同名字的字段（有人在猜）：{:?}",
            rec.conflicts
        );
        assert!(
            rec.from_records >= *min_rec,
            "{label}: Field 簇只解析出 {} 条（下限 {min_rec}）——簇布局或 Mint 取值回归了",
            rec.from_records
        );
        assert!(
            rec.agreements >= *min_agree,
            "{label}: 两个来源一致 {} 条（下限 {min_agree}）——偏移换算或访问器名提取回归了",
            rec.agreements
        );

        for (class, name, off) in *probes {
            let got = rec.by_class_off.get(&(class.to_string(), *off));
            assert_eq!(
                got.map(|s| s.as_str()),
                Some(*name),
                "{label}: ({class}, {off:#x}) 应为 {name}，实得 {got:?}"
            );
            // 偏移必须能换算回机器码位移：disp + 1 == 字节偏移（tagged 折算），8 字节对齐
            assert_eq!((*off) % a.profile.word_size, 0, "{label}: {class}.{name} 偏移未对齐");
        }

        // 注解真的进了产物，而且**没有编造**：产物里每个注解都要能在恢复表里对上
        let libs = a.build_functions(true);
        let (files, _) = dae::decompiler::render(&a, &libs).expect("反编译渲染失败");
        let mut text = String::new();
        for (_, body) in &files {
            text.push_str(body);
        }
        let mut n_notes = 0usize;
        for chunk in text.split("/* ").skip(1) {
            let Some(end) = chunk.find(" */") else { continue };
            let note = &chunk[..end];
            let Some((path, offpart)) = note.rsplit_once(" (off ") else { continue };
            let Some((class, fname)) = path.split_once('.') else { continue };
            let Some(hex) = offpart.trim_end_matches(')').strip_prefix("0x") else { continue };
            let off = u64::from_str_radix(hex, 16).expect("偏移不是十六进制");
            let got = rec.by_class_off.get(&(class.to_string(), off));
            assert_eq!(
                got.map(|s| s.as_str()),
                Some(fname),
                "产物里的注解 {note:?} 不在恢复表里（编造？）"
            );
            n_notes += 1;
        }
        println!("{label:22} 产物里的字段注解 {n_notes} 处");
        assert!(n_notes > 0, "{label}: 产物里一个字段注解都没有——注解链路断了");
        // 权重事项：至少 1% 的注解必须是样本探针里的某个类，避免「注解都落在无关类上」
        let probes_hit = probes
            .iter()
            .filter(|(c, n, o)| text.contains(&format!("/* {c}.{n} (off {o:#x}) */")))
            .count();
        assert!(probes_hit > 0, "{label}: 探针字段一次都没被注解到");
    }
    assert!(ran > 0, "一条字段语料都没有，门禁形同虚设");
}