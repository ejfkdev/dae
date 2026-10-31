//! 健壮性与确定性门禁：**不依赖任何语料的功能性断言**（除标注者外）。
//!
//! 这两类不变量此前只靠手工巡检，没有常驻门禁：
//! 1. **并发度不影响产物字节**——反编译是按库并行渲染的，文件名与「哪个入口地址归哪个库
//!    发射」由一趟顺序预扫描定死，所以 `DAE_DEC_THREADS` 取任何值都必须得到同一棵产物树。
//!    这条一旦破，用户在不同机器上得到的产物就不同，所有存档与对拍都失去意义。
//! 2. **坏输入不许 panic**——截断/随机/空的输入必须走「报错并退出非 0」，而不是崩在解析里
//!    （panic 会打印 backtrace，对批量扫样本的人是灾难：看不出是输入问题还是工具问题）。

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_dae")
}

fn skip_or_fail(msg: &str) {
    if std::env::var_os("DAE_REQUIRE_GATES").is_some() {
        panic!("DAE_REQUIRE_GATES=1，但门禁跳过了：{msg}");
    }
    println!("{msg}");
}

fn corpus() -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testing/decompiler_corpus/sample_arm64");
    p.exists().then_some(p)
}

/// 一份产物树里的所有文件 → (相对路径, 字节)。
fn tree(root: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(b) = std::fs::read(&p) {
                out.push((p.strip_prefix(root).unwrap().to_string_lossy().to_string(), b));
            }
        }
    }
    out.sort();
    out
}

// 需要 --decompile，无 capstone 的构建里没有可测对象
#[cfg(feature = "asm")]
#[test]
fn export_is_byte_identical_at_any_thread_count() {
    let Some(sample) = corpus() else {
        skip_or_fail("缺语料 sample_arm64，跳过并发确定性门禁");
        return;
    };
    let sample = sample.to_string_lossy().to_string();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut trees = Vec::new();
    // 1（串行）与 8（上限）两头都要测：中间档位不必逐个跑，分片边界只在这两端最极端。
    for t in ["1", "8"] {
        let out = root.join("target").join(format!("robust_thr_{t}"));
        let _ = std::fs::remove_dir_all(&out);
        let outs = out.to_string_lossy().to_string();
        let st = Command::new(bin())
            .args([&sample, &outs, "--decompile"])
            .env("DAE_DEC_THREADS", t)
            .output()
            .expect("启动 dae 失败");
        assert_eq!(st.status.code(), Some(0), "DAE_DEC_THREADS={t} 导出失败");
        trees.push((t, tree(&out)));
        let _ = std::fs::remove_dir_all(&out);
    }
    let (t0, a) = &trees[0];
    let (t1, b) = &trees[1];
    assert!(!a.is_empty(), "产物树是空的，这条门禁没量到东西");
    assert_eq!(
        a.len(),
        b.len(),
        "DAE_DEC_THREADS={t0} 与 ={t1} 的文件数不同（{} vs {}）",
        a.len(),
        b.len()
    );
    for ((pa, ba), (pb, bb)) in a.iter().zip(b.iter()) {
        assert_eq!(pa, pb, "文件列表顺序/名字不同：{pa} vs {pb}");
        assert_eq!(
            ba, bb,
            "DAE_DEC_THREADS={t0} 与 ={t1} 的 {pa} 内容不同——\
             并行渲染必须是确定性的（顺序预扫描负责文件名与入口归属）"
        );
    }
}

/// 截断 / 随机 / 空输入：必须**报错退出**，不许 panic。
///
/// 判据是「stderr 里有 `error:`」且「没有 `panicked`」，而不是钉死某个退出码——
/// 退出码按输入不同会落在 1（运行期）或 2（用法），两者都算正确处理。
#[test]
fn malformed_input_never_panics() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let tmp = root.join("target").join("robust_bad_inputs");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("建临时目录");

    // 1) 纯随机字节（没有任何容器魔数）
    let mut rnd = vec![0u8; 4096];
    for (i, b) in rnd.iter_mut().enumerate() {
        *b = ((i * 37 + 11) % 251) as u8; // 确定性伪随机，失败可复现
    }
    std::fs::write(tmp.join("random.bin"), &rnd).unwrap();
    // 2) 空文件
    std::fs::write(tmp.join("empty.bin"), b"").unwrap();
    // 3) 截断的真二进制（只留前 100 KB）
    let mut cases = vec![tmp.join("random.bin"), tmp.join("empty.bin"), tmp.join("trunc.bin")];
    if let Some(sample) = corpus() {
        let d = std::fs::read(&sample).expect("读语料");
        std::fs::write(tmp.join("trunc.bin"), &d[..d.len().min(100_000)]).unwrap();
    } else {
        // 无语料时用随机字节冒充截断件，前两条仍然有效
        std::fs::write(tmp.join("trunc.bin"), &rnd[..512]).unwrap();
        cases.pop();
    }

    for f in cases {
        let out = tmp.join("out");
        let _ = std::fs::remove_dir_all(&out);
        let o = Command::new(bin())
            .args([&f.to_string_lossy().to_string(), &out.to_string_lossy().to_string()])
            .output()
            .expect("启动 dae 失败");
        let so = String::from_utf8_lossy(&o.stdout);
        let se = String::from_utf8_lossy(&o.stderr);
        let all = format!("{so}{se}");
        assert!(
            !all.contains("panicked") && !all.contains("RUST_BACKTRACE"),
            "{} 触发了 panic：\n{se}",
            f.display()
        );
        assert!(
            se.contains("error:"),
            "{} 应当报错并说明原因，实际 stderr：\n{se}",
            f.display()
        );
        assert_ne!(
            o.status.code(),
            Some(0),
            "{} 是坏输入却返回成功——静默产出比报错更糟",
            f.display()
        );
    }
    let _ = std::fs::remove_dir_all(&tmp);
}
