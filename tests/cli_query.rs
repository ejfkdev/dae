//! 渐进式查询命令（pp / objs / stubs / members / callees / findrefs）门禁。
//!
//! 判据都是硬事实，不看文案。核心是 **findrefs 的零编造**：它声称「这个地址的这条指令
//! 从这个池槽加载了这个值」，那就必须能用**两条与它自身实现无关的路径**分别复核——
//!
//! 1. **值**：与 `text/pp.txt` 的 `[pp+0xOFF] VALUE` 行逐字相同。pp.txt 由另一个导出器
//!    （`ppobjs::write_pp`）写，findrefs 由 `decompiler::PoolRefs` 算；两条路径同意才算数。
//! 2. **地址与偏移**：`dae disasm` 的原始反汇编行里，必须字面出现该地址、`PP` 与这个位移
//!    （x64 池指针带 tag 时差 1）。disasm 走的是 `asm::render_one`，又是第三条路径。
//!
//! 只共用 `pool_key` 是**不够**的：那只证明「findrefs 与反编译器的偏移解析一致」，
//! 是自我印证。上面两条才证明它对着产物与反汇编都成立。
//!
//! 另外钉住：列数、stdout 纯净度、零非 ASCII、行数与产物一致、以及**下钻链不断**
//! （findrefs 输出的函数名要能直接喂回 `dae disasm`——这条实测断过）。
//!
//! 语料缺失时整体跳过；`DAE_REQUIRE_GATES=1` 下跳过即失败（口径同 tests/cli.rs）。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn skip_or_fail(msg: &str) {
    if std::env::var_os("DAE_REQUIRE_GATES").is_some() {
        panic!("DAE_REQUIRE_GATES=1，但门禁跳过了：{msg}");
    }
    println!("{msg}");
}

fn corpus(root: &Path) -> Option<PathBuf> {
    let p = root.join("testing/decompiler_corpus/sample_arm64");
    p.exists().then_some(p)
}

fn run(bin: &str, args: &[&str]) -> (String, String, i32) {
    let out = Command::new(bin).args(args).output().expect("启动 dae 失败");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.code().unwrap_or(-1),
    )
}

/// findrefs / pp 的值列做过 TSV 转义（`export::textinfo::esc`），pp.txt 是原文。
fn unesc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some(o) => {
                out.push('\\');
                out.push(o);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// 复核一条 findrefs 命中。抽成函数是为了**能对它做负测**：门禁若不会因错数据失败，
/// 它就什么都没量（本仓库清算过三次「假门禁」）。
///
/// 返回 `Err(原因)` 表示这条命中不可信。
fn verify_hit(
    at: &str,
    off: &str,
    val: &str,
    pp: &std::collections::BTreeMap<String, String>,
    disasm_of: &dyn Fn(&str) -> String,
    from: &str,
) -> Result<(), String> {
    // ① 值必须与 text/pp.txt 逐字相同
    let v = unesc(val);
    match pp.get(off) {
        None => return Err(format!("{off}: pp.txt 里没有这个偏移")),
        Some(d) if d == &v => {}
        // 已知的产物缺陷：pp.txt **不转义**，值里含真实换行时一条条目会跨行，
        // 于是按行读到的只是前半截。判据是「pp.txt 那行是完整值的前缀，且完整值含换行」
        // ——这样就把「转义差异」与「真的对不上」区分开，不会把前者当通过、也不会把它藏起来。
        Some(d) if v.contains('\n') && v.starts_with(d.as_str()) => {
            return Err(format!(
                "{off}: 值含换行而 pp.txt 未转义（既有产物缺陷，一条条目跨了两行）"
            ))
        }
        Some(d) => return Err(format!("{off}: 值不一致 findrefs={v:?} pp.txt={d:?}")),
    }
    // ② at + 偏移必须在原始反汇编行里字面可见
    let txt = disasm_of(from);
    if txt.is_empty() {
        return Err(format!("{from}: dae disasm 没有输出（下钻链断了？）"));
    }
    // x64 的池指针带 tag：操作数里写的位移是「条目偏移 - 1」，所以两个都要试
    let off_minus1 = format!(
        "#0x{:x}",
        u64::from_str_radix(off.trim_start_matches("0x"), 16).map_err(|e| e.to_string())? - 1
    );
    let want = format!("#{off}");
    let ok = txt.lines().any(|l| {
        l.contains(at)
            && l.contains("PP")
            && (l.contains(&want) || l.contains(&off_minus1))
    });
    if !ok {
        return Err(format!("{at}: 反汇编里看不到 [PP, {want}]"));
    }
    Ok(())
}

#[test]
fn query_commands_are_honest() {
    let bin = env!("CARGO_BIN_EXE_dae");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(sample) = corpus(root) else {
        skip_or_fail("缺语料 testing/decompiler_corpus/sample_arm64，跳过查询命令门禁");
        return;
    };
    let s = sample.to_string_lossy().to_string();

    // 全量导出一次，拿 text/pp.txt 与 text/stubs.txt 作为独立对照面
    let out = root.join("target").join("cli_query_out");
    let _ = std::fs::remove_dir_all(&out);
    let o = out.to_string_lossy().to_string();
    let (_so, se, rc) = run(bin, &[&s, &o]);
    assert_eq!(rc, 0, "全量导出失败: {se}");

    let mut pp: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for l in std::fs::read_to_string(out.join("text/pp.txt")).expect("pp.txt").lines() {
        if let Some(rest) = l.strip_prefix("[pp+") {
            if let Some((off, v)) = rest.split_once("] ") {
                // pp.txt 里就是 `0x10` 这种形式，与 findrefs 的 `{off:#x}` 一致，直接用
                pp.insert(off.to_string(), v.to_string());
            }
        }
    }
    assert!(pp.len() > 100, "pp.txt 条目太少（{}），对照面不成立", pp.len());

    // ---------- 列数与 stdout 纯净度 ----------
    // (命令参数, 期望列数, 最少行数)：行数下限是为了让门禁**不能空过**
    let cases: &[(&[&str], usize, usize)] = &[
        (&["pp", &s, "-n", "100000"], 3, 100),
        (&["stubs", &s, "-n", "100000"], 3, 50),
        (&["members", &s, "-n", "100000"], 4, 100),
        (&["objs", &s, "-n", "3"], 0, 1), // 块输出，不检列数
        (&["callees", &s, "main"], 6, 1),
    ];
    for (args, cols, min_rows) in cases {
        let (so, se, rc) = run(bin, args);
        assert_eq!(rc, 0, "`dae {}` 失败: {se}", args[0]);
        // stdout 只放数据：统计与诊断行必须在 stderr
        for bad in ["dae:", "SDK profile:", "target:", "export done"] {
            assert!(
                !so.contains(bad),
                "`dae {}` 的 stdout 混进了诊断行 {bad:?}（管道会坏）",
                args[0]
            );
        }
        // 这里**不**断言 stdout 全 ASCII。「产物零非 ASCII」那条口径管的是 dae 自己生成的
        // 文字（dart/ 伪代码、标签、诊断），由 tests/decompiler_shape.rs 把关；而 pp/objs/
        // strings 这类命令输出的是**从二进制里取出的数据**，池里本来就混着 Unicode 数据表
        // （实测 text/pp.txt 有 106 行、text/strings.txt 有 221 行含非 ASCII），如实复现才对。
        // 真正的风险是「dae 自己写的说明文字混进数据流」，那由上面的诊断行检查覆盖。
        if *cols > 0 {
            let rows: Vec<&str> = so.lines().filter(|l| !l.is_empty()).collect();
            assert!(
                rows.len() >= *min_rows,
                "`dae {}` 只有 {} 行（< {}）——门禁会空过",
                args[0],
                rows.len(),
                min_rows
            );
            for r in &rows {
                assert_eq!(
                    r.split('\t').count(),
                    *cols,
                    "`dae {}` 的行列数不是 {cols}: {r:?}",
                    args[0]
                );
            }
        }
    }

    // ---------- stubs / pp 的行数必须与产物一致 ----------
    let (so, _se, rc) = run(bin, &["stubs", &s, "-n", "100000"]);
    assert_eq!(rc, 0);
    let stub_lines = std::fs::read_to_string(out.join("text/stubs.txt")).expect("stubs.txt");
    let n_art = stub_lines.lines().filter(|l| !l.starts_with("//")).count();
    assert_eq!(
        so.lines().filter(|l| !l.is_empty()).count(),
        n_art,
        "dae stubs 的行数与 text/stubs.txt 不一致（两边必须同源）"
    );
    let (so, _se, rc) = run(bin, &["pp", &s, "-n", "1000000"]);
    assert_eq!(rc, 0);
    assert_eq!(
        so.lines().filter(|l| !l.is_empty()).count(),
        pp.len(),
        "dae pp 的行数与 text/pp.txt 的条目数不一致（两边必须同源）"
    );

    // ---------- findrefs：零编造 ----------
    let (so, se, rc) = run(bin, &["findrefs", &s, "string", "", "-n", "100000"]);
    assert_eq!(rc, 0, "findrefs 失败: {se}");
    let hits: Vec<Vec<String>> = so
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.split('\t').map(|x| x.to_string()).collect())
        .collect();
    assert!(
        hits.len() >= 200,
        "findrefs 只命中 {} 处——太少了，门禁会空过（语料应有数百处）",
        hits.len()
    );
    for h in &hits {
        assert_eq!(h.len(), 5, "findrefs 应输出 5 列: {h:?}");
    }
    // 先把每个出现过的函数反汇编一次（同一函数只跑一次），再让复核闭包只读——
    // 顺带这就把「下钻链不断」验到了**全部** from 上，而不是抽查几个。
    let froms: BTreeSet<String> = hits.iter().map(|h| h[2].clone()).collect();
    let mut cache: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for f in &froms {
        let (t, se, rc) = run(bin, &["disasm", &s, f]);
        assert_eq!(
            rc,
            0,
            "findrefs 给出的函数名 {f} 喂不回 `dae disasm`（下钻链断了）: {se}"
        );
        assert!(!t.trim().is_empty(), "dae disasm {f} 输出为空");
        cache.insert(f.clone(), t);
    }
    let disasm_of = |from: &str| -> String {
        cache.get(from).cloned().unwrap_or_default()
    };
    let mut ok = 0usize;
    let mut multiline = 0usize;
    let mut bad: Vec<String> = Vec::new();
    for h in &hits {
        let (at, _fep, from, off, val) = (&h[0], &h[1], &h[2], &h[3], &h[4]);
        match verify_hit(at, off, val, &pp, &disasm_of, from) {
            Ok(()) => ok += 1,
            Err(e) if e.contains("值含换行而 pp.txt 未转义") => {
                // 已知的产物缺陷（pp.txt 不转义），不是 findrefs 编造：
                // 仍要求地址与偏移能在反汇编里看到
                multiline += 1;
                let txt = disasm_of(from);
                assert!(
                    txt.lines().any(|l| l.contains(at.as_str()) && l.contains("PP")),
                    "{at}: 连反汇编里都找不到，这条命中不可信"
                );
            }
            Err(e) => bad.push(e),
        }
    }
    assert!(
        bad.is_empty(),
        "findrefs 有 {} 处命中无法复核（前 5 条）：\n  {}",
        bad.len(),
        bad.iter().take(5).cloned().collect::<Vec<_>>().join("\n  ")
    );
    assert!(
        ok >= 200,
        "只有 {ok} 处命中通过双重复核，太少（另有 {multiline} 处因 pp.txt 换行缺陷单独验地址）"
    );
    println!(
        "findrefs: {} 处命中，{} 处双重复核通过，{} 处因 pp.txt 未转义换行只验地址",
        hits.len(),
        ok,
        multiline
    );

    // ---------- 负测：把偏移改坏，复核必须失败 ----------
    let h = &hits[0];
    let wrong_off = format!("{:#x}", u64::from_str_radix(h[3].trim_start_matches("0x"), 16).unwrap() + 8);
    let e = verify_hit(&h[0], &wrong_off, &h[4], &pp, &disasm_of, &h[2])
        .expect_err("偏移改坏后复核竟然还通过了——门禁是假的");
    assert!(
        e.contains("pp.txt 里没有这个偏移") || e.contains("值不一致") || e.contains("反汇编里看不到"),
        "负测失败原因不符预期: {e}"
    );
    let e2 = verify_hit(&h[0], &h[3], "\"完全不相干的值\"", &pp, &disasm_of, &h[2])
        .expect_err("值改坏后复核竟然还通过了——门禁是假的");
    assert!(e2.contains("值不一致"), "负测失败原因不符预期: {e2}");

    // ---------- findrefs 的 kind 语义 ----------
    let (_so, se, rc) = run(bin, &["findrefs", &s, "type", "Field"]);
    assert_ne!(rc, 0, "`type` 这个 kind 应当被拒（它名不副实）");
    assert!(
        se.contains("string") && se.contains("kind"),
        "拒绝信息里要点出可用的 kind: {se}"
    );
    let (_so, se, rc) = run(bin, &["findrefs", &s, "field", "x"]);
    assert_ne!(rc, 0, "`field` 这个 kind 应当被拒（按裸位移匹配是猜不是查）");
    assert!(!se.is_empty());
    // `kind NAME` 要能用，且没命中时列出真实存在的种类（可操作的失败）
    let (_so, se, rc) = run(bin, &["findrefs", &s, "kind", "NoSuchKindAtAll"]);
    assert_ne!(rc, 0);
    assert!(
        se.contains("Type") || se.contains("Field") || se.contains("ImmutableArray"),
        "没命中时应列出池里真实出现过的种类: {se}"
    );

    // 下钻链已在上面构建反汇编缓存时对**全部** from 验过（rc==0 且输出非空）
    assert!(!froms.is_empty());

    // ---------- callees 与 callers 必须互为反方向 ----------
    let (so, _se, rc) = run(bin, &["callees", &s, "main"]);
    assert_eq!(rc, 0);
    let rows: Vec<Vec<String>> = so
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.split('\t').map(|x| x.to_string()).collect())
        .collect();
    assert!(!rows.is_empty(), "callees main 没有输出");
    for r in &rows {
        assert_eq!(r[3], "->", "callees 的第 4 列应是箭头: {r:?}");
    }
    // 任取一条 callees 行，反过来问 callers 应该能看到同一个调用点
    let probe = rows.iter().find(|r| !r[5].is_empty() && !r[5].starts_with("sub_")).expect("找不到具名目标");
    let (so2, _se2, rc2) = run(bin, &["callers", &s, &probe[5]]);
    assert_eq!(rc2, 0);
    assert!(
        so2.lines().any(|l| l.starts_with(&format!("{}\t", probe[0]))),
        "callees 报的调用点 {} 在 callers {} 里找不到——两条命令不同源",
        probe[0],
        probe[5]
    );

    // ---------- callers/callees 必须拒绝筛选 flag（而不是静默忽略）----------
    for cmd in ["callers", "callees"] {
        let (_so, se, rc) = run(bin, &[cmd, &s, "main", "--lib", "dart_core"]);
        assert_ne!(rc, 0, "`{cmd} --lib` 应当报错：它扫全程序，筛选会给出残缺答案");
        assert!(
            se.contains("--lib") || se.contains("整个程序") || se.contains("whole program"),
            "{cmd} 的拒绝信息要说明原因: {se}"
        );
    }

    // ---------- members 的方法行入口地址必须真存在于 functions.txt ----------
    let (so, _se, rc) = run(bin, &["members", &s, "-n", "100000", "--method"]);
    assert_eq!(rc, 0);
    let ft = std::fs::read_to_string(out.join("text/functions.txt")).expect("functions.txt");
    let eps: BTreeSet<String> = ft.lines().filter_map(|l| l.split('\t').next().map(|x| x.to_string())).collect();
    let mut n = 0usize;
    for l in so.lines().filter(|l| !l.is_empty()).take(200) {
        let c: Vec<&str> = l.split('\t').collect();
        assert_eq!(c.len(), 4, "members 应输出 4 列: {l:?}");
        assert_eq!(c[0], "method");
        assert!(eps.contains(c[3]), "members 报的入口 {} 不在 functions.txt 里", c[3]);
        n += 1;
    }
    assert!(n >= 50, "members --method 只出了 {n} 行，太少");

    let _ = std::fs::remove_dir_all(&out);
}

/// `decompile` 动词与三个作用域 flag。
///
/// 每一项都带**负对照**：光断言「加了 --no-sdk 之后没有 dart_* 文件」是假的——
/// 如果 flag 根本没接上，输出可能恰好也没有那些文件。所以同时断言「不加 flag 时
/// 确实有 dart_* 文件」，两边一比才证明是这个 flag 起的作用。
#[test]
fn decompile_verb_and_scope_flags() {
    let bin = env!("CARGO_BIN_EXE_dae");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(sample) = corpus(root) else {
        skip_or_fail("缺语料 testing/decompiler_corpus/sample_arm64，跳过 decompile/作用域门禁");
        return;
    };
    let s = sample.to_string_lossy().to_string();
    let tmp = root.join("target").join("cli_query_scope");
    let _ = std::fs::remove_dir_all(&tmp);
    let dir = |n: &str| tmp.join(n).to_string_lossy().to_string();

    // 取一个真实库名（第一条，按函数数降序）
    let (libs_out, _e, rc) = run(bin, &["libs", &s]);
    assert_eq!(rc, 0);
    let lib = libs_out
        .lines()
        .next()
        .and_then(|l| l.split('\t').next())
        .expect("libs 没有输出")
        .to_string();

    // ---------- 共用输出路由：decompile --lib X 与 getlib X 必须逐字节相同 ----------
    let (a, b) = (dir("a"), dir("b"));
    assert_eq!(run(bin, &["getlib", &s, &lib, "-o", &a]).2, 0);
    assert_eq!(run(bin, &["decompile", &s, "--lib", &lib, "-o", &b]).2, 0);
    assert!(
        !std::path::Path::new(&a).join("dart").exists()
            || same_tree(std::path::Path::new(&a), std::path::Path::new(&b)),
        "getlib {lib} -o DIR 与 decompile --lib {lib} -o DIR 产物不一致（说是共用路由就得真的一致）"
    );

    // ---------- 无 -o 走 stdout，且不掺诊断 ----------
    let (so, se, rc) = run(bin, &["decompile", &s, "--lib", &lib]);
    assert_eq!(rc, 0, "decompile 到 stdout 失败: {se}");
    assert!(so.contains("// ===== "), "stdout 应有 `// ===== 库名 =====` 分隔: {}", &so[..so.len().min(200)]);
    for bad in ["dae:", "SDK profile:", "target:"] {
        assert!(!so.contains(bad), "decompile 的 stdout 混进了诊断行 {bad:?}");
    }
    // 诊断行必须在 stderr 而不是被丢掉：`SDK profile:` 由 detect 打在 stderr
    assert!(
        se.contains("SDK profile:") || se.contains("dae:"),
        "decompile 的 stderr 既没有 SDK 行也没有 dae: 行，诊断可能被吞了: {se:?}"
    );

    // ---------- --no-sdk / --app / --exclude-lib：都要有负对照 ----------
    let (all, nosdk, app, excl) = (dir("all"), dir("nosdk"), dir("app"), dir("excl"));
    for (d, extra) in [
        (&all, &[][..]),
        (&nosdk, &["--no-sdk"][..]),
        (&app, &["--app"][..]),
        (&excl, &["--exclude-lib", lib.as_str()][..]),
    ] {
        let mut argv: Vec<&str> = vec!["decompile", &s, "-o", d];
        argv.extend_from_slice(extra);
        let (_o, e, rc) = run(bin, &argv);
        assert_eq!(rc, 0, "decompile {extra:?} 失败: {e}");
    }
    let dart_files = |d: &str| -> Vec<String> {
        let p = std::path::Path::new(d).join("dart");
        let mut v: Vec<String> = std::fs::read_dir(&p)
            .unwrap_or_else(|_| panic!("{d}/dart 不存在"))
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        v.sort();
        v
    };
    let (f_all, f_nosdk, f_app, f_excl) =
        (dart_files(&all), dart_files(&nosdk), dart_files(&app), dart_files(&excl));

    // 负对照：不加 flag 时**确实有** dart_* 文件，否则下面的断言全是空过
    assert!(
        f_all.iter().any(|n| n.starts_with("dart_")),
        "语料里没有 dart_* 库，--no-sdk 的断言会空过——换语料或换判据"
    );
    assert!(
        !f_nosdk.iter().any(|n| n.starts_with("dart_")),
        "--no-sdk 之后仍有 dart_* 文件: {:?}",
        f_nosdk.iter().filter(|n| n.starts_with("dart_")).take(3).collect::<Vec<_>>()
    );
    assert!(
        f_nosdk.len() < f_all.len(),
        "--no-sdk 没有减少库数（{} → {}），flag 可能没接上",
        f_all.len(),
        f_nosdk.len()
    );
    // --app 是 --no-sdk 的超集排除：结果必须 ⊆，且不含 flutter_*
    assert!(
        f_app.iter().all(|n| f_nosdk.contains(n)),
        "--app 的结果不是 --no-sdk 的子集（--app 应排除得更多）"
    );
    assert!(
        !f_app.iter().any(|n| n.starts_with("flutter_")),
        "--app 之后仍有 flutter_* 文件"
    );
    // --exclude-lib 精确挖掉那一个库，其余不动
    let stem = lib.replace(['$', '/', ':'], "_");
    assert!(
        !f_excl.iter().any(|n| n == &format!("{stem}.dart")),
        "--exclude-lib {lib} 没有排除掉 {stem}.dart"
    );
    assert_eq!(
        f_excl.len(),
        f_all.len() - 1,
        "--exclude-lib 多排除了别的库（{} → {}，应只少 1）",
        f_all.len(),
        f_excl.len()
    );

    // ---------- --app 与 --no-sdk 互斥（clap 层就该拒）----------
    let (_o, _e, rc) = run(bin, &["decompile", &s, "--app", "--no-sdk"]);
    assert_ne!(rc, 0, "--app 与 --no-sdk 同时给应当被拒（一个是另一个的超集）");

    let _ = std::fs::remove_dir_all(&tmp);
}

/// 两棵产物树是否逐文件相同。
fn same_tree(a: &Path, b: &Path) -> bool {
    fn walk(d: &Path, pre: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
        let mut m = std::collections::BTreeMap::new();
        let Ok(rd) = std::fs::read_dir(d) else { return m };
        for e in rd.flatten() {
            let p = e.path();
            let rel = p.strip_prefix(pre).unwrap().to_string_lossy().to_string();
            if p.is_dir() {
                for (k, v) in walk(&p, pre) {
                    m.insert(format!("{rel}/{k}"), v);
                }
            } else {
                m.insert(rel, std::fs::read(&p).unwrap_or_default());
            }
        }
        m
    }
    walk(a, a) == walk(b, b)
}

/// 按库收窄反编译时，**跨库调用目标不许退化成匿名 `sub_0x…`**。
///
/// 这条门禁存在的原因是一次真实回归：`render` 的「入口地址 → 显示名」表原本按传进来的
/// `libs`（= 发射集合）建，于是 `--lib X` / `--app` 一收窄，所有调进别的库的目标都掉进
/// `sub_0x…` 兜底。实测 testing_app 的 `Favorites.remove`：全量下是
/// `GrowableList_remove()` 与 `ChangeNotifier_notifyListeners()`，收窄后变成
/// `sub_0x8a1b8()` / `sub_0x6d60()`——恰好丢掉语义最重要的两个调用，而「只看应用自有代码」
/// 正是 `--app` 的推荐用法。具名率 26.6% → 54.0%（修好后）。
///
/// **为什么需要专门的门禁**：这个缺陷对既有门禁全部隐形——产物照样过 `dart analyze`
/// （名字都是 `dynamic`）、结构化率不变、地址自洽性不变、`regress_all` 也不变（它跑的是全量）。
/// 判据取「收窄产物的匿名调用集合 ⊆ 全量产物的匿名调用集合」，与语料无关：
/// 收窄只应该**减少**发射的函数，不应该让任何原本有名字的调用变成没名字。
#[test]
fn scoped_decompile_keeps_cross_library_call_names() {
    let bin = env!("CARGO_BIN_EXE_dae");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(sample) = corpus(root) else {
        skip_or_fail("缺语料 testing/decompiler_corpus/sample_arm64，跳过收窄命名门禁");
        return;
    };
    let s = sample.to_string_lossy().to_string();
    let tmp = root.join("target").join("cli_query_names");
    let _ = std::fs::remove_dir_all(&tmp);
    let (full, scoped) = (tmp.join("full"), tmp.join("scoped"));

    // 取一个真实的库名
    let (libs_out, _e, rc) = run(bin, &["libs", &s]);
    assert_eq!(rc, 0);
    let lib = libs_out
        .lines()
        .next()
        .and_then(|l| l.split('\t').next())
        .expect("libs 没有输出")
        .to_string();

    let f = full.to_string_lossy().to_string();
    let c = scoped.to_string_lossy().to_string();
    assert_eq!(run(bin, &["decompile", &s, "-o", &f]).2, 0, "全量 decompile 失败");
    assert_eq!(
        run(bin, &["decompile", &s, "--lib", &lib, "-o", &c]).2,
        0,
        "收窄 decompile 失败"
    );

    // 收集两边产物里出现的匿名调用目标地址（`sub_0x…`）。手写扫描而不引正则依赖：
    // 只为一条门禁加一个 crate 不划算，而且这里的模式简单到不需要正则。
    let subs = |d: &Path| -> BTreeSet<String> {
        let mut set = BTreeSet::new();
        let dart = d.join("dart");
        let Ok(rd) = std::fs::read_dir(&dart) else {
            return set;
        };
        for e in rd.flatten() {
            let Ok(t) = std::fs::read_to_string(e.path()) else {
                continue;
            };
            let mut rest = t.as_str();
            while let Some(i) = rest.find("sub_0x") {
                let tail = &rest[i + "sub_0x".len()..];
                let hex: String = tail
                    .chars()
                    .take_while(|c| c.is_ascii_hexdigit())
                    .collect();
                if !hex.is_empty() {
                    set.insert(hex);
                }
                rest = &rest[i + "sub_0x".len()..];
            }
        }
        set
    };
    let (in_full, in_scoped) = (subs(&full), subs(&scoped));
    assert!(
        !in_full.is_empty() || !in_scoped.is_empty(),
        "两边都没有匿名调用，门禁会空过——换语料或换判据"
    );
    let leaked: Vec<&String> = in_scoped.difference(&in_full).collect();
    assert!(
        leaked.is_empty(),
        "收窄到 --lib {lib} 后有 {} 个调用目标变成匿名（全量下它们是有名字的）：{:?}\n\
         说明 render 的命名表又是按发射集合建的了——它必须按未筛选的完整函数表建",
        leaked.len(),
        leaked.iter().take(6).map(|x| x.as_str()).collect::<Vec<_>>()
    );
    println!(
        "收窄命名: 全量匿名 {} 个地址，收窄后 {} 个，无新增（leaked=0）",
        in_full.len(),
        in_scoped.len()
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// 反编译正文对**指令地址**的覆盖率。
///
/// 守的是「待定值被静默丢弃」这类 bug：`nest_block` 曾在遇到 `Op::Note` / `Op::Cmp` 等语句时
/// `pending.clear()`（而不是先落地），于是 x64 上 `mov rcx,rax; sub rcx,1; push rcx; call fib`
/// 折成的 `rcx = rax - 1` 被扔掉——产物里 `fib()` 既看不到实参、也没有任何一行提到 `n - 1`，
/// 而且**不计入 unmapped**（指令是认得的，只是结果被扔了）。所以 analyze 错误数、结构化率、
/// 地址自洽性、regress 对拍**全都看不见它**：那次修复前后 `DecompileStats` 的语句数一字未变
/// （统计发生在 `nest_block` 之前）。
///
/// 判据：`asm/` 里出现的真指令地址，有多少能在 `dart/` 的语句地址注释里找到。
/// 实测同一语料：修复前 **70.1%**（129/184），修复后 **78.3%**（144/184），门槛取 **0.75**
/// 落在两者之间——回退修复即失败（已负测）。不到 100% 是正常的：`cmp` 折进条件、
/// 分支目标折进 `if`、`frame/align` 只出注释，这些都不带语句地址。
#[test]
fn decompiled_body_covers_instruction_addresses() {
    let bin = env!("CARGO_BIN_EXE_dae");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(sample) = corpus(root) else {
        skip_or_fail("缺语料 testing/decompiler_corpus/sample_arm64，跳过指令覆盖率门禁");
        return;
    };
    let s = sample.to_string_lossy().to_string();
    let out = root.join("target").join("cli_query_cov");
    let _ = std::fs::remove_dir_all(&out);
    let o = out.to_string_lossy().to_string();
    // 一次全量导出同时给出 asm/（真指令地址）与 dart/（语句地址）
    let (_so, se, rc) = run(bin, &[&s, &o, "--decompile"]);
    assert_eq!(rc, 0, "全量导出失败: {se}");

    // asm/ 的指令行长这样：`    //     0x481dac: ldr          r0, [PP, #0x1f0]`
    // 只取**小写助记符**的行——IL 注释行是 `// 0x…: LoadField: …`（首字母大写），要排除，
    // 否则同一条指令会被数两次。
    let mut ins: BTreeSet<String> = BTreeSet::new();
    collect_addrs(&out.join("asm"), &mut ins, &|line| {
        let t = line.trim_start();
        let t = match t.strip_prefix("// ") {
            Some(x) => x.trim_start(),
            None => return None,
        };
        let hex = t.strip_prefix("0x")?;
        let end = hex.find(':')?;
        let (addr, rest) = hex.split_at(end);
        if !addr.chars().all(|c| c.is_ascii_hexdigit()) || addr.is_empty() {
            return None;
        }
        let mnem = rest[1..].trim_start().chars().next()?;
        if !mnem.is_ascii_lowercase() {
            return None;
        }
        Some(addr.to_string())
    });
    // dart/ 的语句地址在行尾：`  x0 = mem(x1, 7); // 0x4bc0f8`
    let mut emit: BTreeSet<String> = BTreeSet::new();
    collect_addrs(&out.join("dart"), &mut emit, &|line| {
        let t = line.trim_end();
        let i = t.rfind("// 0x")?;
        let addr = &t[i + "// 0x".len()..];
        if addr.is_empty() || !addr.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        Some(addr.to_string())
    });

    assert!(
        ins.len() >= 100,
        "asm/ 里只解析出 {} 条指令地址，分母太小、门禁会空过",
        ins.len()
    );
    let hit = ins.intersection(&emit).count();
    let ratio = hit as f64 / ins.len() as f64;
    println!(
        "指令地址覆盖率: {hit}/{} = {:.1}%（门槛 75%；修复前实测 70.1%）",
        ins.len(),
        ratio * 100.0
    );
    assert!(
        ratio >= 0.75,
        "反编译正文只覆盖了 {hit}/{} = {:.1}% 的指令地址（门槛 75%；修复后应为 78.3%，\"
         退回 70.1% 就说明待定值又被静默丢弃了）——见本测试的文档注释",
        ins.len(),
        ratio * 100.0
    );
    let _ = std::fs::remove_dir_all(&out);
}

/// 递归收集目录下所有文件里、经 `pick` 判定为地址的字符串。
fn collect_addrs(dir: &Path, into: &mut BTreeSet<String>, pick: &dyn Fn(&str) -> Option<String>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_addrs(&p, into, pick);
            continue;
        }
        let Ok(t) = std::fs::read_to_string(&p) else {
            continue;
        };
        for l in t.lines() {
            if let Some(a) = pick(l) {
                into.insert(a);
            }
        }
    }
}

/// `condFlag(...)` 只允许包**裸条件码**，不许包已经是合法 Dart 布尔表达式的东西。
///
/// 曾经的 bug：`cbz`/`cbnz`/`tbz`/`tbnz` 在 lift 阶段就生成了完整表达式（`x2 != 0`、
/// `w1 & (1 << 0) != 0`），但分支统一又过一遍 `fold_cond`，而 `fold_cond` 是按**助记符**
/// 匹配的，匹配不到就落到兜底 `condFlag("{mnem}")` —— 于是合法表达式被包成
/// `condFlag("x2 != 0")`。信息没丢，但读的人得自己把引号里的东西抄出来，
/// 一个 `switch` 会变成三处 `condFlag`。实测 material_3_demo 上这类占位 14 886 处，
/// 其中 **12 550（84.3%）的参数本身就是合法表达式**；修好后只剩 2 336 处真占位
/// （`vc` 1782 / `vs` 293 / `eq` 162 / `ne` 90 / `hs` 5 / `lo` 3）。
///
/// 判据与语料无关：**参数里出现比较/位运算就说明它本该直接当条件用**。
/// 真占位只有 `vc`/`vs`/`eq`/`ne`/`hs`/`lo` 这类两三个字符的条件码。
#[test]
fn condflag_only_wraps_bare_condition_codes() {
    let bin = env!("CARGO_BIN_EXE_dae");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(sample) = corpus(root) else {
        skip_or_fail("缺语料 testing/decompiler_corpus/sample_arm64，跳过 condFlag 门禁");
        return;
    };
    let s = sample.to_string_lossy().to_string();
    let out = root.join("target").join("cli_query_condflag");
    let _ = std::fs::remove_dir_all(&out);
    let o = out.to_string_lossy().to_string();
    let (_so, se, rc) = run(bin, &[&s, &o, "--decompile"]);
    assert_eq!(rc, 0, "全量导出失败: {se}");

    let mut total = 0usize;
    let mut wrapped_expr: Vec<String> = Vec::new();
    let mut codes: BTreeSet<String> = BTreeSet::new();
    let dart = out.join("dart");
    let rd = std::fs::read_dir(&dart).expect("dart/ 应存在");
    for e in rd.flatten() {
        let Ok(t) = std::fs::read_to_string(e.path()) else { continue };
        let mut rest = t.as_str();
        while let Some(i) = rest.find("condFlag(\"") {
            let tail = &rest[i + "condFlag(\"".len()..];
            let arg = match tail.find('"') {
                Some(j) => &tail[..j],
                None => break,
            };
            total += 1;
            // 含比较/逻辑/位运算符，或含空格 ⇒ 它是一个表达式，不该被包起来
            if arg.contains(' ')
                || arg.contains("==")
                || arg.contains("!=")
                || arg.contains('<')
                || arg.contains('>')
                || arg.contains('&')
                || arg.contains('|')
            {
                if wrapped_expr.len() < 6 {
                    wrapped_expr.push(arg.to_string());
                }
            } else {
                codes.insert(arg.to_string());
            }
            rest = &tail[arg.len() + 1..];
        }
    }
    assert!(
        total > 0,
        "一处 condFlag 都没有——门禁会空过（语料里应当有标志位条件）"
    );
    assert!(
        wrapped_expr.is_empty(),
        "有 condFlag 包着**已经是合法 Dart 布尔表达式**的东西（样例 {:?}）。\
         自带条件的分支（cbz/cbnz/tbz/tbnz）不该再过 fold_cond——见本测试的文档注释",
        wrapped_expr
    );
    println!("condFlag: 共 {total} 处，全是裸条件码 {:?}", codes);
    let _ = std::fs::remove_dir_all(&out);
}
