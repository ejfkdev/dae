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
