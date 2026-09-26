//! 渐进式命令行（子命令）门禁。
//!
//! 判据都是硬事实，不看文案：
//! 1. **stdout 是数据通道**：查询/定点反编译的 stdout 里不许出现统计与诊断行
//!    （`dae:` / `target:` / `SDK profile` 只能走 stderr），否则管道就没法用；
//! 2. **选出来的是全量的子集**：`--lib X` 与 `getclass` 得到的函数名集合，必须能在
//!    全量导出里一一对上——选择器偏了就是静默丢产物；
//! 3. **筛选真的生效**：`--lib X --decompile` 的 dart/ 只含该库，且函数数与全量里该库相等；
//! 4. 产物零非 ASCII（仓库口径：导出物一律英文）。
//!
//! 语料缺失（`testing/decompiler_corpus/sample_arm64` 未编译）时整体跳过。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn corpus(root: &Path) -> Option<PathBuf> {
    let p = root.join("testing/decompiler_corpus/sample_arm64");
    p.exists().then_some(p)
}

fn run(bin: &str, args: &[&str]) -> (String, String, i32) {
    let out = Command::new(bin)
        .args(args)
        .output()
        .expect("启动 dae 失败");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.code().unwrap_or(-1),
    )
}

/// 从伪代码正文里抓函数名。**只认函数头** `dynamic <name>() {`：
/// 函数体内的局部声明也是 `dynamic x0;`，认错会把局部变量当成函数（试过，会误判）。
fn fn_names(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|l| {
            let t = l.trim();
            let n = t.strip_prefix("dynamic ")?.strip_suffix("() {")?;
            (!n.is_empty() && !n.contains(' ') && !n.contains(';')).then(|| n.to_string())
        })
        .collect()
}

#[test]
fn progressive_cli() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(sample) = corpus(root) else {
        println!("progressive_cli: 无语料（先跑 testing/decompiler_corpus/build.sh）——跳过");
        return;
    };
    let bin = env!("CARGO_BIN_EXE_dae");
    let sample_s = sample.display().to_string();

    // ---- info：能自报容器/架构/SDK ----
    let (out, _e, rc) = run(bin, &["info", &sample_s]);
    assert_eq!(rc, 0, "info 退出码");
    assert!(out.contains("container\tmacho"), "info 应报出容器：{out}");
    assert!(out.contains("arch\tarm64"), "info 应报出架构：{out}");
    assert!(!out.contains("SDK profile:"), "stdout 不该有诊断行：{out}");

    // ---- libs / classes / functions：TSV 列数稳定，且能把库名喂回去 ----
    let (libs, _e, rc) = run(bin, &["libs", &sample_s]);
    assert_eq!(rc, 0);
    let first_lib = libs
        .lines()
        .next()
        .expect("至少一个库")
        .split('\t')
        .next()
        .unwrap()
        .to_string();
    for l in libs.lines() {
        assert_eq!(l.split('\t').count(), 4, "libs 行应为 4 列：{l}");
    }

    let (classes, _e, rc) = run(bin, &["classes", &sample_s, "--lib", &first_lib]);
    assert_eq!(rc, 0);
    assert!(!classes.is_empty(), "--lib {first_lib} 应选中至少一个类");

    let (funcs, _e, rc) = run(bin, &["functions", &sample_s, "--lib", &first_lib]);
    assert_eq!(rc, 0);
    for l in funcs.lines() {
        assert_eq!(l.split('\t').count(), 5, "functions 行应为 5 列：{l}");
    }

    // ---- 全量导出，作为比对的基准 ----
    let full = std::env::temp_dir().join("dae_cli_gate_full");
    let _ = std::fs::remove_dir_all(&full);
    let (_o, _e, rc) = run(
        bin,
        &[&sample_s, &full.display().to_string(), "--decompile"],
    );
    assert_eq!(rc, 0, "全量导出失败");
    let full_fn: BTreeSet<String> = std::fs::read_dir(full.join("dart"))
        .expect("dart/ 目录")
        .filter_map(|e| std::fs::read_to_string(e.ok()?.path()).ok())
        .flat_map(|t| fn_names(&t))
        .collect();
    assert!(!full_fn.is_empty(), "全量导出应有函数");

    // ---- 筛选导出：是子集，且只含该库 ----
    let sel = std::env::temp_dir().join("dae_cli_gate_sel");
    let _ = std::fs::remove_dir_all(&sel);
    let (o, _e, rc) = run(
        bin,
        &[
            &sample_s,
            &sel.display().to_string(),
            "--decompile",
            "--lib",
            &first_lib,
        ],
    );
    assert_eq!(rc, 0, "筛选导出失败：{o}");
    let sel_files = std::fs::read_dir(sel.join("dart")).expect("筛选后 dart/ 目录");
    let mut sel_fn: BTreeSet<String> = BTreeSet::new();
    let mut n_files = 0usize;
    for e in sel_files {
        let p = e.unwrap().path();
        let stem = p.file_stem().unwrap().to_string_lossy().to_string();
        assert!(
            stem.starts_with(&first_lib.replace(['$', '/', ':'], "_")),
            "筛选后的产物不该含其它库：{}",
            p.display()
        );
        n_files += 1;
        sel_fn.extend(fn_names(&std::fs::read_to_string(&p).unwrap()));
    }
    assert!(n_files > 0, "筛选后应有产物");
    assert!(!sel_fn.is_empty());
    let missing: Vec<&String> = sel_fn.difference(&full_fn).collect();
    assert!(
        missing.is_empty(),
        "筛选产物里的函数必须都在全量里（选择器偏了）：{missing:?}"
    );
    // 该库在全量里的函数数 = 筛选后的函数数（同一份函数集）
    let full_for_lib: BTreeSet<String> = full_fn
        .iter()
        .filter(|f| sel_fn.contains(*f))
        .cloned()
        .collect();
    assert_eq!(
        full_for_lib.len(),
        sel_fn.len(),
        "筛选结果与全量中该库的函数集合应一致"
    );

    // ---- getclass：stdout 只有伪代码，且函数是全量的子集 ----
    let (classes_all, _e, _rc) = run(bin, &["classes", &sample_s, "--lib", "decompiler_corpus"]);
    let cls = classes_all
        .lines()
        .find_map(|l| {
            let name = l.split('\t').nth(2)?;
            (!name.is_empty()).then(|| name.to_string())
        })
        .expect("样本里应有至少一个具名类");
    let (got, err, rc) = run(bin, &["getclass", &sample_s, &cls]);
    assert_eq!(rc, 0, "getclass 失败：{err}");
    let got_fn = fn_names(&got);
    assert!(!got_fn.is_empty(), "getclass 应产出伪代码");
    for f in &got_fn {
        assert!(
            full_fn.contains(f),
            "getclass 产出的函数 {f} 不在全量里"
        );
    }
    for bad in ["SDK profile:", "target:", "dae:", "export done"] {
        assert!(!got.contains(bad), "getclass 的 stdout 不该含 {bad}：{got}");
    }
    assert!(got.is_ascii(), "产物必须零非 ASCII");

    // ---- getmethod：命中一个方法 ----
    let one = got_fn.iter().next().unwrap().clone();
    let (g1, e1, rc) = run(bin, &["getmethod", &sample_s, &one]);
    assert_eq!(rc, 0, "getmethod 失败：{e1}");
    assert_eq!(fn_names(&g1).len(), 1, "getmethod 只该产出一个函数：{g1}");

    // ---- 没命中：非零退出 + 给提示 ----
    let (_o2, e2, rc) = run(bin, &["getclass", &sample_s, "NoSuchClassAtAll"]);
    assert_ne!(rc, 0, "没命中应非零退出");
    assert!(e2.contains("nothing matched"), "应说明没命中：{e2}");

    // ---- fields：字段清单是 TSV（类 / 字段 / 来源 / 偏移），来源只有两种取值 ----
    let (fl, _e, rc) = run(bin, &["fields", &sample_s, "-n", "100000"]);
    assert_eq!(rc, 0, "fields 退出码");
    let mut n_rows = 0usize;
    for l in fl.lines().filter(|l| !l.is_empty()) {
        let cols: Vec<&str> = l.split('\t').collect();
        assert_eq!(cols.len(), 4, "fields 每行 4 列：{l}");
        assert!(matches!(cols[2], "rec" | "accessor"), "来源列只该是 rec/accessor：{l}");
        let off = cols[3].strip_prefix("0x").expect("偏移应是 0x..");
        let off = u64::from_str_radix(off, 16).expect("偏移应是十六进制");
        assert_eq!(off % 8, 0, "字对齐：{l}");
        n_rows += 1;
    }
    assert!(n_rows > 0, "样本里应至少恢复出一个字段名");
    assert!(fl.is_ascii(), "字段产物必须零非 ASCII");
    // 导出产物里同一张表必须落在 text/fields.txt
    let ft = std::fs::read_to_string(full.join("text/fields.txt")).expect("应有 text/fields.txt");
    assert!(ft.lines().count() == n_rows, "fields 子命令与 text/fields.txt 行数应一致");

    // ---- help：列出子命令 ----
    let (h, _e, rc) = run(bin, &["help"]);
    assert_eq!(rc, 0);
    for c in ["getclass", "getlib", "getmethod", "callers", "disasm", "fields"] {
        assert!(h.contains(c), "help 应列出 {c}");
    }
    let _ = std::fs::remove_dir_all(&full);
    let _ = std::fs::remove_dir_all(&sel);
}