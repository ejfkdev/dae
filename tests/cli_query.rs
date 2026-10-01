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
            // 合法的条件码只有 1–3 个小写字母（arm64: eq/ne/lt/gt/le/ge/lo/hs/hi/ls/
            // mi/pl/vs/vc/al/nv/cs/cc；x86: e/ne/l/le/g/ge/b/be/a/ae/s/ns/o/no/p/np/c/nc）。
            //
            // ⚠️ 原来的判据只查「含不含空格或比较/逻辑/位运算符」，**太弱**：
            // `condFlag("isSmi(w0)")` 一个都不含，于是大摇大摆过了门禁——而它是把
            // 已经还原好的语义判断又塞回字符串字面量里，比不还原更糟。
            // 改成「必须是纯小写字母短串」，任何表达式形态都会被挡下。
            if !arg.chars().all(|c| c.is_ascii_lowercase()) || arg.is_empty() || arg.len() > 3 {
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

/// `cset`/`csetm` 必须落地成三元式：每条指令在**它所属函数**的函数体里都要留下产物。
///
/// 这个门禁守的是两个互相掩盖的缺陷（都只在「读了源码才知道该有什么」时才看得见，
/// `dart analyze` 与指令覆盖率门禁全都测不到）：
///
/// 1. `lift_one` 的 cset 分支曾直接用裸条件码拼 `(ne) ? 1 : 0`。`ne` 不是 Dart 标识符，
///    本该报 undefined_identifier——`csel`/`csinc` 走 `sel_cond()`/`fold_cond()` 那条路，
///    cset 漏在了 `lift()` 折叠臂的 `matches!` 列表外面。
/// 2. `nest_block` 的 `Expr::Text` 分支曾不做待定值替换（`Expr::Mem` 做），而 pending
///    按 dst 建键 ⇒ 紧随的 `x2 = (x2 << 1)` 直接覆盖掉 cset 那条，语句整条消失。
///
/// (2) 把 (1) 的非法 Dart 吞掉了，所以 analyze 一直 0 错误；cset 的地址又被折进后一条
/// 语句、本来就不该单独出现，所以覆盖率门禁也看不见。**净效果是静默的错误值**：
/// 实测 stress2 样例 `Level.get_tag`（源码 `int get rank => this == Level.low ? 0 : 1`
/// 被 AOT 内联成 `cmp x1, <Level.low>; cset x2, ne; lsl x2, x2, #1`），修复前产物只剩
/// `x2 = x2 << 1`，而 x2 还是上面 `x2 = 4`（插值数组长度）的残值；修复后是
/// `x2 = ((x1 != BARRIER) ? 1 : 0) << 1`。
///
/// 不变量按函数统计：函数体里 `? 1 : 0` / `? -1 : 0` 的个数 ≥ 该函数 raw 反汇编注释里
/// `cset`/`csetm` 的条数。基线 v0.1.9 在 sample_arm64 上是 **8 条指令 ↔ 0 个三元式**
/// （本门禁必红），修复后 8 ↔ 8。顺带钉住 (1)：函数体里不许出现裸条件码三元式。
#[test]
fn cset_instructions_materialize_as_ternaries() {
    let bin = env!("CARGO_BIN_EXE_dae");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(sample) = corpus(root) else {
        skip_or_fail("缺语料 testing/decompiler_corpus/sample_arm64，跳过 cset 落地门禁");
        return;
    };
    let s = sample.to_string_lossy().to_string();
    let out = root.join("target").join("cli_query_cset");
    let _ = std::fs::remove_dir_all(&out);
    let o = out.to_string_lossy().to_string();
    let (_so, se, rc) = run(bin, &[&s, &o, "--decompile"]);
    assert_eq!(rc, 0, "全量导出失败: {se}");

    /// raw 反汇编注释行是否为 cset/csetm：`//  0x4bd4dc: cset x2, ne`
    fn is_cset_comment(line: &str) -> bool {
        let t = line.trim_start();
        let Some(t) = t.strip_prefix("//") else { return false };
        let t = t.trim_start();
        let Some(t) = t.strip_prefix("0x") else { return false };
        let Some(i) = t.find(':') else { return false };
        if t[..i].is_empty() || !t[..i].chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
        let m = t[i + 1..].trim_start();
        m.starts_with("cset ") || m.starts_with("csetm ")
    }
    /// 函数头：`dynamic Level_get_tag() {`。前导声明区里的
    /// `dynamic mem(dynamic a, ...) => null;` 不以 `{` 结尾，不会误判。
    fn is_fn_header(line: &str) -> bool {
        let t = line.trim_end();
        t.starts_with("dynamic ") && t.ends_with(") {") && t.contains('(')
    }
    fn count_ternaries(line: &str) -> usize {
        line.matches("? 1 : 0").count() + line.matches("? -1 : 0").count()
    }
    /// 裸条件码三元式 `(ne) ? ...`：条件码没被包进 condFlag、也没折成真条件
    const CODES: [&str; 18] = [
        "eq", "ne", "lt", "gt", "le", "ge", "lo", "hs", "hi", "ls", "mi", "pl", "vs", "vc", "al",
        "nv", "cs", "cc",
    ];

    let dart = out.join("dart");
    let rd = std::fs::read_dir(&dart).expect("dart/ 应存在");
    let mut total_csets = 0usize;
    let mut total_tern = 0usize;
    let mut bad: Vec<String> = Vec::new();
    let mut bare: Vec<String> = Vec::new();
    for e in rd.flatten() {
        let Ok(text) = std::fs::read_to_string(e.path()) else { continue };
        // raw 注释在函数头**之前**，所以先攒着，遇到函数头再归属给随后的函数体
        let mut pending_csets = 0usize;
        // Some((函数名, 该函数 raw 注释里的 cset 条数, 函数体里已数到的三元式个数))
        let mut cur: Option<(String, usize, usize)> = None;
        let fname_of = |e: &std::path::Path| e.file_name().unwrap_or_default().to_string_lossy().to_string();
        let file = fname_of(&e.path());
        for line in text.lines() {
            let t = line.trim_start();
            if t.starts_with("//") {
                if cur.is_none() && is_cset_comment(line) {
                    pending_csets += 1;
                    total_csets += 1;
                }
                continue;
            }
            if is_fn_header(line) {
                if let Some((n, c, tr)) = cur.take() {
                    total_tern += tr;
                    if tr < c && bad.len() < 8 {
                        bad.push(format!("{file}::{n}: {c} 条 cset/csetm 只落地了 {tr} 个三元式"));
                    }
                }
                let n = line
                    .trim_start_matches("dynamic ")
                    .split('(')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                cur = Some((n, pending_csets, 0));
                pending_csets = 0;
                continue;
            }
            let Some((ref n, _c, ref mut tr)) = cur else { continue };
            // ⚠️ 只认**第 0 列**的 `}` 作为函数结束。函数体里的 `if`/`while` 块闭合是
            // 缩进的 `  }`，用 `trim_start()` 比会把函数体提前截断（这个门禁自己先错过一次）。
            if line == "}" {
                let (n, c, tr) = cur.take().unwrap();
                total_tern += tr;
                if tr < c && bad.len() < 8 {
                    bad.push(format!("{file}::{n}: {c} 条 cset/csetm 只落地了 {tr} 个三元式"));
                }
                continue;
            }
            *tr += count_ternaries(line);
            for code in CODES {
                let pat = format!("({code}) ?");
                if line.contains(&pat) && bare.len() < 6 {
                    bare.push(format!("{n}: {}", line.trim()));
                }
            }
        }
        if let Some((n, c, tr)) = cur.take() {
            total_tern += tr;
            if tr < c && bad.len() < 8 {
                bad.push(format!("{file}::{n}: {c} 条 cset/csetm 只落地了 {tr} 个三元式"));
            }
        }
    }

    assert!(
        total_csets > 0,
        "语料里一条 cset/csetm 都没有——门禁会空过（sample_arm64 实测有 8 条）"
    );
    assert!(
        bare.is_empty(),
        "函数体里出现**裸条件码**三元式（样例 {bare:?}）。条件码必须包成 \
         condFlag(\"cc\") 或用上一条 cmp 折成真条件，否则 `ne` 这类不是 Dart 标识符"
    );
    assert!(
        bad.is_empty(),
        "有 cset/csetm 指令没有落地成三元式（{bad:?}）——定义被静默丢弃，\
         产物里会剩下引用残值的语句。见本测试的文档注释"
    );
    println!(
        "cset/csetm 落地: {} 条指令 ↔ {} 个三元式（基线 v0.1.9 是 {} ↔ 0）",
        total_csets, total_tern, total_csets
    );
    let _ = std::fs::remove_dir_all(&out);
}

/// x86 `setcc` 必须落地成三元式，而不是退化成 `// unmapped: setne dl`。
///
/// `setcc` 是 arm64 `cset` 的对应物（条件成立取 1），语义同样依赖前一条 `cmp`/`test`。
/// v0.1.9 完全没有 setcc 的 lift 分支，所以它落到 `Op::Other` —— 好处是**诚实**
/// （产物里印 `// unmapped: setne dl`、计入 unmapped 指标，不像 cset 那样整条消失），
/// 坏处是那个布尔条件白丢了：读的人只看到「这里有个没认出的指令」。
///
/// 现在 `set<cc>` 走与 `cset` 同一条折叠路径（`sel_cond` + `fold_cond`，条件码→等价
/// 跳转助记符按 ISA 取前缀：arm64 `b.`、x86 `j`），条件码只认 `fold_cond` 里真有
/// 对应跳转的白名单，**不在白名单里的一律不接管**（继续 unmapped，绝不编造
/// `condFlag("j…")` 这种名字）。
///
/// 实测 T4_blank（elf x64）：raw 注释里 8 条 setcc ↔ 函数体 8 个 `? 1 : 0`、unmapped
/// 残留 0；基线 v0.1.9 是 8 条**全部** unmapped、0 个三元式（本门禁必红）。
/// hello_3.12.2（macho x64）同样 5 ↔ 5。
#[test]
fn x86_setcc_materializes_as_ternary() {
    let bin = env!("CARGO_BIN_EXE_dae");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sample = root.join("testing/variants/T4_blank/libapp.so");
    if !sample.exists() {
        skip_or_fail("缺语料 testing/variants/T4_blank/libapp.so，跳过 setcc 门禁");
        return;
    }
    let s = sample.to_string_lossy().to_string();
    let out = root.join("target").join("cli_query_setcc");
    let _ = std::fs::remove_dir_all(&out);
    let o = out.to_string_lossy().to_string();
    let (_so, se, rc) = run(bin, &[&s, &o, "--decompile"]);
    assert_eq!(rc, 0, "全量导出失败: {se}");

    /// 与 `src/decompiler.rs::is_x86_setcc` 的白名单一致（改动要同步两边）
    const CC: [&str; 26] = [
        "e", "z", "ne", "nz", "l", "b", "nae", "le", "be", "na", "g", "a", "nbe", "ge", "ae",
        "nb", "s", "ns", "o", "no", "c", "nc", "p", "np", "pe", "po",
    ];
    /// raw 注释行 `//  0x17a50: setne dl` → Some("ne")
    fn setcc_of(line: &str) -> Option<&str> {
        let t = line.trim_start().strip_prefix("//")?.trim_start();
        let t = t.strip_prefix("0x")?;
        let i = t.find(':')?;
        let hex = &t[..i];
        if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let cc = t[i + 1..].trim_start().strip_prefix("set")?;
        // 后面必须还有操作数（`setne dl`），否则不是 setcc
        if !cc.contains(' ') {
            return None;
        }
        let code = cc.split(' ').next()?;
        CC.into_iter().find(|c| *c == code)
    }

    let dart = out.join("dart");
    let rd = std::fs::read_dir(&dart).expect("dart/ 应存在");
    let mut instr = 0usize;
    let mut tern = 0usize;
    let mut unmapped: Vec<String> = Vec::new();
    for e in rd.flatten() {
        let Ok(text) = std::fs::read_to_string(e.path()) else { continue };
        let mut in_body = false;
        for line in text.lines() {
            let t = line.trim_start();
            if t.starts_with("//") {
                if !in_body && setcc_of(line).is_some() {
                    instr += 1;
                }
                // 白名单内的 setcc 出现在 unmapped 注释里 = lift 分支没接住
                if let Some(u) = t.strip_prefix("// unmapped: set") {
                    let code = u.split(|c: char| !c.is_ascii_alphanumeric()).next().unwrap_or("");
                    if CC.contains(&code) && unmapped.len() < 6 {
                        unmapped.push(t.to_string());
                    }
                }
                continue;
            }
            let tr = line.trim_end();
            if tr.starts_with("dynamic ") && tr.ends_with(") {") && tr.contains('(') {
                in_body = true;
                continue;
            }
            if in_body {
                if line == "}" {
                    in_body = false;
                    continue;
                }
                tern += line.matches("? 1 : 0").count();
            }
        }
    }

    assert!(
        instr > 0,
        "语料里一条白名单内的 setcc 都没有——门禁会空过（T4_blank 实测 8 条）"
    );
    assert!(
        unmapped.is_empty(),
        "白名单内的 setcc 仍被当成 unmapped（样例 {unmapped:?}）——lift 分支没接住，\
         前一条 cmp/test 的布尔条件就白丢了"
    );
    assert!(
        tern >= instr,
        "setcc 落地不全：raw 注释里 {instr} 条，函数体里只有 {tern} 个 `? 1 : 0` 三元式"
    );
    println!("x86 setcc 落地: {instr} 条指令 ↔ {tern} 个三元式，unmapped 残留 0（基线 v0.1.9 是 {instr} ↔ 0）");
    let _ = std::fs::remove_dir_all(&out);
}

/// arm64 的 `wN`（32 位）与 `xN`（64 位）是**同一个物理寄存器的两个视图**：写 `wN` 会把
/// `xN` 的高 32 位清零。产物里它们是 `dynamic w4; dynamic x4;` 两个独立变量，所以
/// 「先写 `wN`、之后读 `xN`、中间没有对 `xN` 的写」会读到 `xN` 的**旧值**（或从未赋值的值）
/// —— 这不是少一行注释，是**静默的错误值**。
///
/// 实测 stress3 样例的 `hashBytes`：源码 `h = ((h << 5) | (h >> 27)) & 0xffffffff`
/// 编译成 `w4 = w1 << 5; w6 = w1 >> 27; ... (x4 | x6)`，修复前产物就是
/// `x0 = ((x4 | x6) >> 0) & 0xffffffff`，而 x4/x6 是几个指令之前的陈旧值；
/// 修复后是 `x0 = ((((w1 << 5) & 0xffffffff) | ((w1 >> 0x1b) & 0xffffffff)) >> 0) & 0xffffffff`。
///
/// 修法是每写一次 `wN` 就补一条别名赋值 `xN = wN & 0xffffffff`（`nest_block` 会把它折进
/// 后续表达式）。**不能**简单把 `wN` 改名成 `xN`：`w4 = w1 + w2` 的真值是
/// `(w1 + w2) mod 2^32`，改名就丢了截断；只改写入端又会让后续**读** `wN` 的地方变成未定义变量。
///
/// 门禁判据与实测口径一致：material_3_demo 上修复前 **3 590 个读点 / 1 135 个函数（7.6%）**，
/// 修复后 **16 / 13（0.1%）**。门槛定 40 处——远高于修复后、远低于修复前。
#[test]
fn w_register_write_aliases_x_register() {
    let bin = env!("CARGO_BIN_EXE_dae");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(sample) = corpus(root) else {
        skip_or_fail("缺语料 testing/decompiler_corpus/sample_arm64，跳过 w/x 别名门禁");
        return;
    };
    let s = sample.to_string_lossy().to_string();
    let out = root.join("target").join("cli_query_wx");
    let _ = std::fs::remove_dir_all(&out);
    let o = out.to_string_lossy().to_string();
    let (_so, se, rc) = run(bin, &[&s, &o, "--decompile"]);
    assert_eq!(rc, 0, "全量导出失败: {se}");

    let dart = out.join("dart");
    let rd = std::fs::read_dir(&dart).expect("dart/ 应存在");
    let mut w_writes = 0usize; // 非空断言用：语料里必须真的有 w 寄存器写入
    let mut stale: Vec<String> = Vec::new();
    let mut stale_total = 0usize;
    for e in rd.flatten() {
        let Ok(text) = std::fs::read_to_string(e.path()) else { continue };
        let mut cur: Option<String> = None;
        // 写过 wN、且其后未写 xN 的编号集合
        let mut pending_w: BTreeSet<String> = BTreeSet::new();
        for line in text.lines() {
            let t = line.trim_end();
            if t.starts_with("dynamic ") && t.ends_with(") {") && t.contains('(') {
                cur = Some(
                    t.trim_start_matches("dynamic ")
                        .split('(')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_string(),
                );
                pending_w.clear();
                continue;
            }
            if line == "}" {
                cur = None;
                pending_w.clear();
                continue;
            }
            if t.starts_with("//") || cur.is_none() {
                continue;
            }
            // 只看语句行（行尾带地址注释），跳过局部声明 `dynamic w4;`
            let Some(ai) = t.rfind("// 0x") else { continue };
            let code = &t[..ai];
            let Some(eq) = code.find('=') else { continue };
            let lhs = code[..eq].trim();
            let rhs = &code[eq + 1..];
            if let Some(n) = lhs.strip_prefix('w') {
                if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) {
                    pending_w.insert(n.to_string());
                    w_writes += 1;
                }
            } else if let Some(n) = lhs.strip_prefix('x') {
                if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) {
                    pending_w.remove(n); // 写了 xN，之前的 wN 就不再是它的最新值
                }
            }
            // RHS 里读到的 xN，若其编号正处在「只写过 wN」状态 ⇒ 陈旧读
            let bytes = rhs.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'x'
                    && (i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_'))
                {
                    let j = i + 1;
                    let mut k = j;
                    while k < bytes.len() && bytes[k].is_ascii_digit() {
                        k += 1;
                    }
                    if k > j
                        && (k >= bytes.len()
                            || !(bytes[k].is_ascii_alphanumeric() || bytes[k] == b'_'))
                    {
                        let n = &rhs[j..k];
                        if pending_w.contains(n) {
                            stale_total += 1;
                            if stale.len() < 6 {
                                stale.push(format!("{}: x{n} 读自陈旧的 w{n} | {}", cur.clone().unwrap_or_default(), t.trim()));
                            }
                        }
                        i = k;
                        continue;
                    }
                }
                i += 1;
            }
        }
    }

    assert!(
        w_writes >= 20,
        "语料里只解析出 {w_writes} 处 w 寄存器写入——门禁会空过"
    );
    assert!(
        stale_total <= 40,
        "有 {stale_total} 处「写 wN 之后读 xN、中间未写 xN」的陈旧读（样例 {stale:?}）。\
         修复前 material_3_demo 是 3590 处 / 1135 个函数，修复后 16 处；\
         写 wN 时必须补一条 `xN = wN & 0xffffffff` 别名赋值"
    );
    println!(
        "w/x 寄存器别名: {w_writes} 处 w 写入，陈旧 x 读 {stale_total} 处（门槛 40；修复前 material_3_demo 实测 3590）"
    );
    let _ = std::fs::remove_dir_all(&out);
}

/// 产物里不许出现 `ppmem(`——它是**寄存器名子串误匹配**捏造出来的标识符。
///
/// 池加载判定原先写的是 `ops.contains(&rl.pp)`。Dart arm64 的池指针 PP 物理寄存器名是
/// `x27`，而位移文本 `#0x27` 里**正好含有子串 `x27`**，于是 `stur x17, [x3, #0x27]`
/// 被误判成池加载、返回 `Expr::Pool(0x27)`：
///
/// 1. **store 被当成赋值**，方向反转，`memSet(x3, 0x27, x17)` 这个写**彻底消失**；
/// 2. `Expr::Pool` 渲染成 `pp[0x27]`，再经出口的 `sanitize_mem_refs` 把 `[..]` 改写成
///    `mem(..)`，于是产物里出现凭空的 `ppmem(0x27)`；
/// 3. load 侧丢基址：`ldur x1,[x0,#0x27]` 与二级解引用 `ldur x2,[x1,#0x27]` 渲染成
///    同一个 `ppmem(0x27)`，双重间接被别名成同一个值。
///
/// 修法是改用**词边界匹配**（`contains_word`，与 `replace_word` 同一套边界定义）。
/// 实测 Reqable（arm64、dart 3.3.4）：`ppmem(` **1411 → 0**，`mem(..., 0x27*)` 恢复
/// **744 处**，被吞掉的 `memSet(..., 0x27..., ...)` 全部回来；agent 报的原始案例
/// `Agb.uzd` 从 `x17 = ppmem(0x27);` 变成
/// `x17 = "autoCapture" /* pp+0x2a608 */; memSet(x3, 0x27, x17);`——顺带把一个此前丢失的
/// 字符串字面量也恢复了。诊断指纹是「**纯前缀相关**」：16 种 ppmem 偏移全部以 `0x27`
/// 开头、而 `mem(..., 0x27*)` 零幸存，`mem(PP,0x5270)`/0x26x/0x28x 全正常。
#[test]
fn no_register_substring_false_positives_in_output() {
    let bin = env!("CARGO_BIN_EXE_dae");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(sample) = corpus(root) else {
        skip_or_fail("缺语料 testing/decompiler_corpus/sample_arm64，跳过 ppmem 门禁");
        return;
    };
    let s = sample.to_string_lossy().to_string();
    let out = root.join("target").join("cli_query_ppmem");
    let _ = std::fs::remove_dir_all(&out);
    let o = out.to_string_lossy().to_string();
    let (_so, se, rc) = run(bin, &[&s, &o, "--decompile"]);
    assert_eq!(rc, 0, "全量导出失败: {se}");

    let dart = out.join("dart");
    let rd = std::fs::read_dir(&dart).expect("dart/ 应存在");
    let mut ppmem: Vec<String> = Vec::new();
    let mut stores = 0usize;
    let mut loads = 0usize;
    for e in rd.flatten() {
        let Ok(text) = std::fs::read_to_string(e.path()) else { continue };
        for line in text.lines() {
            if line.trim_start().starts_with("//") {
                continue; // 只看正文语句，不看 raw 反汇编注释
            }
            if line.contains("ppmem(") && ppmem.len() < 6 {
                ppmem.push(line.trim().to_string());
            }
            if line.contains("memSet(") {
                stores += 1;
            }
            if line.contains("mem(") {
                loads += 1;
            }
        }
    }
    // 非空断言：门禁要真的量到内存访问，否则「0 处 ppmem」是空过
    assert!(
        stores >= 50 && loads >= 500,
        "语料里只解析出 {stores} 个 memSet / {loads} 个 mem —— 分母太小，门禁会空过"
    );
    assert!(
        ppmem.is_empty(),
        "产物里出现 {n} 处捏造标识符 `ppmem(`（样例 {ppmem:?}）——寄存器名匹配退化成子串匹配了：\
         PP 的物理名 `x27` 是位移文本 `0x27` 的子串。必须用 contains_word 按词边界匹配",
        n = ppmem.len()
    );
    println!("无寄存器子串误匹配: {stores} 个 memSet / {loads} 个 mem，ppmem 0 处（修复前 Reqable 实测 1411）");
    let _ = std::fs::remove_dir_all(&out);
}

/// 位测试（`tbz`/`tbnz`）的条件里不许出现 32 位视图 `wN`，必须是同一物理寄存器的 `xN`。
///
/// 产物里 `wN` 与 `xN` 是两个独立的 Dart 变量，而编译器**极少**显式写 w 形式：
/// `blr LR; tbz w0, #4` 里的 w0 是调用返回的 x0 的低半部，全函数只写过 `x0`，
/// 于是 `w0` 从未被赋值 ⇒ 条件在对 `null` 求值。这是「写 wN 后读 xN」
/// （见 `w_register_write_aliases_x_register`）的**镜像方向**。
///
/// 换成 `xN` 是**可证明精确**的、不需要补掩码：`tbz`/`tbnz` 对 w 形式的位号必然 ≤ 31，
/// 而对 k < 32，`wN` 的第 k 位与 `xN` 的第 k 位恒等（`wN` 就是 `xN` 的低 32 位），
/// 与高位内容、与之前谁写过它都无关。实测 Reqable：这类陈旧读 **1690 → 0**，
/// 1671 处位测试改为读真正被写入的 `xN`。
#[test]
fn bit_test_conditions_use_the_64bit_view() {
    let bin = env!("CARGO_BIN_EXE_dae");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(sample) = corpus(root) else {
        skip_or_fail("缺语料 testing/decompiler_corpus/sample_arm64，跳过位测试门禁");
        return;
    };
    let s = sample.to_string_lossy().to_string();
    let out = root.join("target").join("cli_query_tbz");
    let _ = std::fs::remove_dir_all(&out);
    let o = out.to_string_lossy().to_string();
    let (_so, se, rc) = run(bin, &[&s, &o, "--decompile"]);
    assert_eq!(rc, 0, "全量导出失败: {se}");

    let dart = out.join("dart");
    let rd = std::fs::read_dir(&dart).expect("dart/ 应存在");
    let mut w_form: Vec<String> = Vec::new();
    let mut x_form = 0usize;
    for e in rd.flatten() {
        let Ok(text) = std::fs::read_to_string(e.path()) else { continue };
        for line in text.lines() {
            if line.trim_start().starts_with("//") {
                continue; // 只看正文语句，不看 raw 反汇编注释
            }
            // 位测试的形态固定是 `<reg> & (1 << <k>) == 0` / `!= 0`
            let Some(i) = line.find("& (1 << ") else { continue };
            let before = &line[..i];
            // 取 `& (1 <<` 之前最后一个**非空**字母数字 token 就是被测寄存器。
            // ⚠️ 不能直接 `.last()`：`if (x0 ` 尾部有空格，split 出来的最后一段是空串
            // （第一版就是这么写的，结果一处都没匹配上，被自己的防空过断言拦住了）。
            let reg = before
                .split(|c: char| !c.is_ascii_alphanumeric())
                .rev()
                .find(|t| !t.is_empty())
                .unwrap_or("");
            if reg.len() < 2 {
                continue;
            }
            let (tag, num) = reg.split_at(1);
            if !num.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            match tag {
                "w" => {
                    if w_form.len() < 6 {
                        w_form.push(line.trim().to_string());
                    }
                }
                "x" => x_form += 1,
                _ => {}
            }
        }
    }
    assert!(
        x_form >= 20,
        "语料里只找到 {x_form} 处 x 形式位测试——分母太小，门禁会空过"
    );
    assert!(
        w_form.is_empty(),
        "有 {} 处位测试仍读 32 位视图 `wN`（样例 {w_form:?}）。w 形式在产物里是独立变量、\
         而机器码几乎从不显式写它 ⇒ 条件在对未赋值的 null 求值。\
         tbz/tbnz 的位号 ≤ 31，用同一物理寄存器的 xN 是精确等价的",
        w_form.len()
    );
    println!("位测试用 64 位视图: {x_form} 处 xN、0 处 wN（修复前 Reqable 实测 1690 处读 wN）");
    let _ = std::fs::remove_dir_all(&out);
}

/// 棘轮门禁：**无 else 的空 `if`** 数量不许增长。
///
/// 形态判据（两种必须分开数，混在一起这个门禁就没有意义）：
/// * 闭合行**正好是** `}` ⇒ then 分支是空的**且没有 else** —— 机器码里那条条件分支的
///   目标处理块没有落到 then 里，是**真丢了分支边**。实例：`Glb.anon_closure_2` 的
///   `cmp x0, BARRIER; b.eq #0xf00bdc` 渲染成 `if (x0 == BARRIER) { }` 然后直接落下去，
///   而 0xf00bdc 的 lazy-field 处理块确实存在于同一文件里、却挂在另一条守卫下。
/// * 闭合行以 `} else` 开头 ⇒ 空 then + 有 else，这是**良性**的跳跃形态（语句都在 else
///   或共享尾部里）。已抽查对照 raw 反汇编确认没有丢东西，**不要把它当 bug 修**——
///   在 sample_arm64 上它是 2560 处 vs 真丢的 109 处，一起「修」会把产物改坏。
///
/// 这条门禁**不断言已经修好**，只钉住当前数量：改结构化器时任何让分支边丢得更多的副作用
/// 会立刻报红。修好之后应当把上限往下调（并且调之前先确认下降来自真的补回了分支，
/// 而不是来自把 `} else` 那种形态误判掉）。
#[test]
fn empty_if_without_else_does_not_grow() {
    let bin = env!("CARGO_BIN_EXE_dae");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(sample) = corpus(root) else {
        skip_or_fail("缺语料 testing/decompiler_corpus/sample_arm64，跳过空 if 棘轮门禁");
        return;
    };
    let s = sample.to_string_lossy().to_string();
    let out = root.join("target").join("cli_query_emptyif");
    let _ = std::fs::remove_dir_all(&out);
    let o = out.to_string_lossy().to_string();
    let (_so, se, rc) = run(bin, &[&s, &o, "--decompile"]);
    assert_eq!(rc, 0, "全量导出失败: {se}");

    // 2026-09-28 在 sample_arm64 上实测：无 else 空 if = 109，空 then 有 else = 2560，
    // `if (` 总数 5445。上限取实测值，即「不许变差」。
    const CEIL_NO_ELSE: usize = 109;
    let dart = out.join("dart");
    let rd = std::fs::read_dir(&dart).expect("dart/ 应存在");
    let mut no_else = 0usize;
    let mut with_else = 0usize;
    let mut ifs = 0usize;
    let mut examples: Vec<String> = Vec::new();
    for e in rd.flatten() {
        let Ok(text) = std::fs::read_to_string(e.path()) else { continue };
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.contains("if (") {
                ifs += 1;
            }
            if i == 0 {
                continue;
            }
            let prev = lines[i - 1].trim();
            if !prev.ends_with('{') || !prev.contains("if (") {
                continue;
            }
            let t = line.trim();
            if t == "}" {
                no_else += 1;
                if examples.len() < 5 {
                    examples.push(format!("{}: {prev}", e.file_name().to_string_lossy()));
                }
            } else if t.starts_with("} else") {
                with_else += 1;
            }
        }
    }
    assert!(
        ifs >= 1000,
        "只解析出 {ifs} 个 `if (`——分母太小，门禁会空过（sample_arm64 实测 5445）"
    );
    assert!(
        with_else >= 500,
        "只解析出 {with_else} 个「空 then + 有 else」——判据大概没匹配上良性形态，\
         那么 no_else 的计数也不可信（sample_arm64 实测 2560）"
    );
    assert!(
        no_else <= CEIL_NO_ELSE,
        "无 else 的空 if 从 {CEIL_NO_ELSE} 涨到 {no_else}（样例 {examples:?}）——\
         结构化器丢了更多分支边。注意别把「空 then + 有 else」（{with_else} 处，良性跳跃形态）\
         算进来，也不要为了压低这个数字去改判据"
    );
    println!(
        "空 if 棘轮: 无 else {no_else} / 上限 {CEIL_NO_ELSE}；空 then 有 else {with_else}（良性）；`if (` 共 {ifs}"
    );
    let _ = std::fs::remove_dir_all(&out);
}

/// 棘轮门禁：**栈溢出检查守卫**缺失的数量不许增长。
///
/// Dart 在调用与循环回边前有一段固定序列：`ldr BARRIER, [THR, #stack_limit]`、
/// `cmp SP, BARRIER`、`b.ls <溢出 stub>`。产物里守卫形态是
/// `BARRIER = mem(THR, 0x48); if (SP <= BARRIER) { sub_0x…(); }`。
///
/// 已知缺陷：**`cmp` 与 `b.ls` 两条指令在正文里完全消失**，溢出 stub 于是从
/// 「仅 SP<=BARRIER 时调用」变成**无条件调用**。注意那个调用是 out-of-line 的
/// `b.ls` 目标块（实例里加载在 0x4bbdac、调用在 0x4bbe30），结构化器把它当直线语句
/// 接在了加载后面。同一函数的**序言**守卫渲染是正确的，所以 `lift` 没问题，
/// 丢失发生在结构化器发射那一步。material_3_demo 上按 stub 调用点算是 69 处。
///
/// **判据必须是「加载之后紧跟一个未命名 stub 调用」**，不能只数 `BARRIER = mem(THR,`：
/// THR 的其它偏移也被加载进 BARRIER 用于别的比较（实测 `mem(THR, 0x88)` 后面跟的是
/// `x0 = mem(...); if (x0 != BARRIER)`，与栈检查无关）。sample_arm64 上宽松判据给
/// 1007 次加载 / 差值 249，收紧后是 **113 处 / 99 个函数**，且三例的偏移都是 0x48、
/// 紧跟同一个 stub 地址——宽松判据会把真值淹没在 2 倍多的噪声里。
///
/// **已修**（2026-09-28）：根因是 `loop_shape` 的兜底臂返回 `succ(h, 0)`＝**分支目标**，
/// 于是 out-of-line 的溢出处理块被当成循环体入口，而守卫的 `if` 随循环头路径的 `continue`
/// 消失。判别「这是守卫而不是循环条件」用的是**侧块形状**——处理块的形态是
/// `bl <stub>; b <落空块>`，即它的无条件跳转目标正好是头块的落空后继
/// （`is_rejoin_side_block`）。⚠️ 不能用「目标在不在循环内」判别：处理块跳回循环内，
/// 会被循环检测标成 in_loop，那个判据恒假（第一版就是这么失败的）。
/// 实测 sample_arm64：无守卫 **113 → 0**、有守卫 758 → **875**、`if (` 5445 → 5562；
/// **7 个语料的结构化率逐一完全不变**，material_3_demo 与 Reqable 全量 `dart analyze` 0 错误，
/// 非 `dart/` 产物逐字节一致。上限因此收到 0。
#[test]
fn stack_check_guards_do_not_regress() {
    let bin = env!("CARGO_BIN_EXE_dae");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(sample) = corpus(root) else {
        skip_or_fail("缺语料 testing/decompiler_corpus/sample_arm64，跳过栈检查守卫门禁");
        return;
    };
    let s = sample.to_string_lossy().to_string();
    let out = root.join("target").join("cli_query_stackck");
    let _ = std::fs::remove_dir_all(&out);
    let o = out.to_string_lossy().to_string();
    let (_so, se, rc) = run(bin, &[&s, &o, "--decompile"]);
    assert_eq!(rc, 0, "全量导出失败: {se}");

    // 2026-09-28 修复前 sample_arm64 实测 113 处 / 99 个函数；**修复后为 0**（守卫 758 → 875）。
    // 上限收到 0：缺陷已修，这条门禁从此强制「不许再出现」。
    const CEIL_UNGUARDED: usize = 0;
    /// 未命名 stub 调用：`sub_0x4c3c40();`
    fn is_stub_call(t: &str) -> bool {
        let Some(h) = t.strip_prefix("sub_0x") else { return false };
        let Some(k) = h.find("();") else { return false };
        let hex = &h[..k];
        !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit())
    }

    let dart = out.join("dart");
    let rd = std::fs::read_dir(&dart).expect("dart/ 应存在");
    let mut unguarded = 0usize;
    let mut guarded = 0usize;
    let mut fns_hit = 0usize;
    let mut examples: Vec<String> = Vec::new();
    for e in rd.flatten() {
        let Ok(text) = std::fs::read_to_string(e.path()) else { continue };
        // 收集每个函数的**语句行**（跳过 raw 注释、局部声明、空行）
        let mut stmts: Vec<&str> = Vec::new();
        let mut fname = String::new();
        let mut hit_here = 0usize;
        for line in text.lines() {
            let t = line.trim();
            if line.starts_with("dynamic ") && line.trim_end().ends_with(") {") {
                fname = line
                    .trim_start_matches("dynamic ")
                    .split('(')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                stmts.clear();
                continue;
            }
            // 只认**第 0 列**的 `}` 作为函数结束（体内 if/while 的闭合是缩进的）
            if line == "}" {
                for w in stmts.windows(2) {
                    if w[0].contains("BARRIER = mem(THR,") && is_stub_call(w[1]) {
                        unguarded += 1;
                        hit_here += 1;
                        if examples.len() < 5 {
                            examples.push(format!("{fname}: {} | {}", w[0], w[1]));
                        }
                    }
                }
                guarded += stmts
                    .iter()
                    .filter(|l| l.contains("if (SP <= BARRIER)"))
                    .count();
                if hit_here > 0 {
                    fns_hit += 1;
                }
                stmts.clear();
                hit_here = 0;
                continue;
            }
            if t.is_empty() || t.starts_with("//") || t.starts_with("dynamic ") {
                continue;
            }
            stmts.push(t);
        }
    }
    assert!(
        guarded >= 300,
        "只解析出 {guarded} 个 `if (SP <= BARRIER)` 守卫——判据大概没匹配上         （sample_arm64 实测 758），无守卫计数不可信"
    );
    // 上限已是 0，对 usize 而言 `<=` 与 `==` 等价（clippy: absurd_extreme_comparisons）
    assert!(
        unguarded == CEIL_UNGUARDED,
        "无守卫的栈检查从 {CEIL_UNGUARDED} 涨到 {unguarded}（{fns_hit} 个函数，样例 {examples:?}）——         结构化器丢了更多 `cmp SP, BARRIER; b.ls`，溢出 stub 变成无条件调用"
    );
    println!(
        "栈检查守卫棘轮: 无守卫 {unguarded} / 上限 {CEIL_UNGUARDED}（{fns_hit} 个函数）；有守卫 {guarded}"
    );
    let _ = std::fs::remove_dir_all(&out);
}

/// 棘轮门禁：`local_0` 的出现次数不许增长。
///
/// `local_0` = 「相对 SP/FP 位移为 0 的栈槽」。它本身合法（`str x0, [SP]` 传参就是它），
/// 但**post-index 的栈操作会错误地落在这里**：
///
/// ```text
/// str q0, [SP, #-0x10]!   ->  local_m10 = q0     pre-index：先 SP -= 0x10 再存 ⇒ 槽位 -0x10
/// ldr q0, [SP], #0x10     ->  q0 = local_0       post-index：先在 SP 处取、再 SP += 0x10
/// ```
///
/// 机器层面这两条访问**同一个槽位**，产物却给了两个名字，读者无法把它们对上。
/// 根因不是命名规则错：dae 按**方括号内的位移**命名槽位，而 `[SP]` 没有位移，
/// 所以 `local_0` 在这个模型下是自洽的。要让两个名字一致，必须**跨指令跟踪 SP 的增减**
/// （pre-index 减、post-index 加）——那是真实状态，不是改名；在没有它之前强行统一
/// 就是把猜测当事实写进产物。material_3_demo 上 51 个函数是这个形态。
///
/// 所以这条门禁只钉住数量：真做了 SP 跟踪之后 `local_0` 应当**下降**，届时把上限调低。
/// 上限涨了就说明有别的东西也开始把栈访问错误地归到位移 0。
#[test]
fn post_index_stack_slots_do_not_regress() {
    let bin = env!("CARGO_BIN_EXE_dae");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(sample) = corpus(root) else {
        skip_or_fail("缺语料 testing/decompiler_corpus/sample_arm64，跳过 post-index 槽位门禁");
        return;
    };
    let s = sample.to_string_lossy().to_string();
    let out = root.join("target").join("cli_query_postidx");
    let _ = std::fs::remove_dir_all(&out);
    let o = out.to_string_lossy().to_string();
    let (_so, se, rc) = run(bin, &[&s, &o, "--decompile"]);
    assert_eq!(rc, 0, "全量导出失败: {se}");

    // 2026-09-28 sample_arm64 实测：local_0 出现 942 次、分布在 518 个函数
    const CEIL_LOCAL0: usize = 942;
    let dart = out.join("dart");
    let rd = std::fs::read_dir(&dart).expect("dart/ 应存在");
    let mut n = 0usize;
    let mut slots = 0usize; // 所有 local_* 槽位引用，作非空断言的分母
    for e in rd.flatten() {
        let Ok(text) = std::fs::read_to_string(e.path()) else { continue };
        let b = text.as_bytes();
        let mut i = 0usize;
        while i + 7 <= b.len() {
            if &b[i..i + 7] == b"local_0"
                && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'))
                && (i + 7 >= b.len() || !(b[i + 7].is_ascii_alphanumeric() || b[i + 7] == b'_'))
            {
                n += 1;
                i += 7;
                continue;
            }
            if &b[i..i + 6] == b"local_" {
                slots += 1;
            }
            i += 1;
        }
    }
    assert!(
        slots >= 5000,
        "只解析出 {slots} 处 local_* 槽位引用——分母太小，门禁会空过"
    );
    assert!(
        n <= CEIL_LOCAL0,
        "local_0 从 {CEIL_LOCAL0} 涨到 {n} 处——更多栈访问被错误地归到「位移 0」。\
         post-index 形态（`ldr q0, [SP], #0x10`）本应与配对的 pre-index `local_m10` 同名，\
         那需要跨指令跟踪 SP，见本测试的文档注释"
    );
    println!("post-index 槽位棘轮: local_0 {n} / 上限 {CEIL_LOCAL0}（local_* 引用共 {slots}）");
    let _ = std::fs::remove_dir_all(&out);
}

/// `dae disasm <binary> 0xADDR` 必须能反汇编**未命名的 stub**，并且对两个表都不认识的地址
/// **报错而不是猜一个窗口长度**。
///
/// 为什么这条能力是必需的：占直接调用 **54%** 的目标是未命名 stub（material_3_demo 实测
/// 42 759 个 `sub_0x…()` 调用点、只有 **346 个不同地址**，其中 89.8% 在 stub 表里）。
/// stub 没有 Code 对象、从不出现在 `build_functions` 里，所以按名字的路径**结构上够不到它们**
/// ——在加这条之前，产物里最该看的那部分代码根本无法查看。
///
/// 「不猜长度」是硬要求：猜一个窗口会反汇编到**别的字节**上，而输出看起来完全正常
/// （本项目在快照定位上踩过三次这类「指标全绿但读的是别的代码」的坑）。
#[test]
fn disasm_accepts_address_and_refuses_unknown() {
    let bin = env!("CARGO_BIN_EXE_dae");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(sample) = corpus(root) else {
        skip_or_fail("缺语料 testing/decompiler_corpus/sample_arm64，跳过 disasm 地址门禁");
        return;
    };
    let s = sample.to_string_lossy().to_string();

    // 取一个真实存在的函数入口地址
    let (so, se, rc) = run(bin, &["functions", &s]);
    assert_eq!(rc, 0, "functions 失败: {se}");
    let entry = so
        .lines()
        .find_map(|l| l.split('\t').next())
        .expect("函数表应至少有一行");
    assert!(entry.starts_with("0x"), "入口地址形态不对: {entry}");

    // 1) 已知入口：必须出反汇编，且真的有指令行（防空过）
    let (o1, e1, r1) = run(bin, &["disasm", &s, entry]);
    assert_eq!(r1, 0, "按地址反汇编已知入口失败: {e1}");
    assert!(
        o1.contains("// entry:"),
        "输出里没有 entry 头：{}",
        &o1[..o1.len().min(200)]
    );
    let insn_lines = o1
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("//") && !t.contains(": 0x") && t[2..].trim_start().starts_with("0x")
        })
        .count();
    assert!(
        insn_lines >= 1,
        "按地址反汇编只出了 {insn_lines} 行指令注释——大概没真的反汇编"
    );

    // 2) 两个表都不认识的地址：必须**非零退出**并说明不猜长度
    let (o2, e2, r2) = run(bin, &["disasm", &s, "0xdeadbeef00"]);
    assert_ne!(r2, 0, "未知地址竟然成功了（rc={r2}），说明它在猜窗口长度");
    let msg = format!("{o2}{e2}");
    assert!(
        msg.contains("stub-table") || msg.contains("stub 表"),
        "错误消息没说明「不在函数表也不在 stub 表」: {msg}"
    );
    println!(
        "disasm 按地址: 已知入口 {entry} 出 {insn_lines} 行指令；未知地址 rc={r2} 且拒绝猜长度"
    );
}

/// 零编造校验：`stubs.txt` 里每一个 `RuntimeCallStub_0x…` 名字，都必须能在**该地址的真实
/// 反汇编**里复核出「保存全部寄存器 / 严格逆序恢复」的形状。
///
/// 这条门禁刻意走**独立路径**取证——用 `dae disasm <bin> 0xADDR` 的文本输出重新数一遍
/// `stp`/`ldp`，不复用 `callgraph::runtime_stub_name` 的代码。否则分类器写错时，
/// 门禁会用同一段错逻辑自证清白（`alloc_stub_naming` 也是这个套路）。
///
/// 判据（与实现同源但独立复核）：≥6 组 `stp` 压栈、≥6 组 `ldp` 弹回、有 `ret`，
/// 且**第一组 stp 的寄存器对 == 最后一组 ldp 的寄存器对**（镜像）。
/// 名字里保留地址而**不猜具体是哪个 runtime entry**：形状可证到「调用约定转换包装」这一层，
/// 但 profile 的 `runtime_offsets` 只有 7 个键、不含该形状里出现的 `THR+0x188`/`THR+0x488`，
/// 所以再往下命名就是编造（判据同撤回 `isSmi` 那次）。
#[test]
fn runtime_call_stub_names_are_provable() {
    let bin = env!("CARGO_BIN_EXE_dae");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sample = root.join("testing/decompiler_corpus/sample_arm64");
    if !sample.exists() {
        skip_or_fail("缺语料 testing/decompiler_corpus/sample_arm64，跳过 RuntimeCallStub 门禁");
        return;
    }
    let s = sample.to_string_lossy().to_string();
    let out = root.join("target").join("cli_query_rtstub");
    let _ = std::fs::remove_dir_all(&out);
    let o = out.to_string_lossy().to_string();
    let (_so, se, rc) = run(bin, &[&s, &o]);
    assert_eq!(rc, 0, "全量导出失败: {se}");

    let stubs = std::fs::read_to_string(out.join("text/stubs.txt")).expect("stubs.txt 应存在");
    let mut named: Vec<String> = Vec::new();
    for line in stubs.lines() {
        let c: Vec<&str> = line.split('\t').collect();
        if c.len() >= 4 && c[3].starts_with("RuntimeCallStub_0x") {
            named.push(c[0].to_string());
        }
    }
    if named.is_empty() {
        // 该语料可能没有这个形状的 stub；不是失败，但要说明，避免被误读成「验过了」
        println!("runtime stub 命名: 本语料 0 条（无该形状），门禁未产生断言");
        let _ = std::fs::remove_dir_all(&out);
        return;
    }
    let regs = |o: &str| -> Vec<String> {
        o.split('[')
            .next()
            .unwrap_or("")
            .split(',')
            .map(|t| t.trim().to_ascii_lowercase())
            .filter(|t| !t.is_empty())
            .collect()
    };
    let mut bad: Vec<String> = Vec::new();
    for addr in &named {
        let (od, _ed, rd) = run(bin, &["disasm", &s, addr]);
        assert_eq!(rd, 0, "disasm {addr} 失败");
        let mut stp: Vec<Vec<String>> = Vec::new();
        let mut ldp: Vec<Vec<String>> = Vec::new();
        let mut has_ret = false;
        for line in od.lines() {
            // 指令行形如 `//     0x8ec5c: stp          x24, x25, [x15, #-0x10]!`
            // ⚠️ 冒号在**地址之后**，不是 `": 0x"`（第一版按 `": 0x"` 找，一条都没解析到，
            // 于是把两条正确命名的 stub 全报成不合格）。IL 分组行 `// 0x…: EnterFrame`
            // 也会走到这里，但它的助记符是大写开头的名字，匹配不上 stp/ldp/ret，无害。
            let t = line.trim();
            let Some(t) = t.strip_prefix("//") else { continue };
            let t = t.trim_start();
            let Some(t) = t.strip_prefix("0x") else { continue };
            let Some(k) = t.find(':') else { continue };
            if t[..k].is_empty() || !t[..k].chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            let body = t[k + 1..].trim();
            let mut it = body.split_whitespace();
            let m = it.next().unwrap_or("").to_ascii_lowercase();
            let ops = it.collect::<Vec<_>>().join(" ");
            match m.as_str() {
                "stp" => stp.push(regs(&ops)),
                "ldp" => ldp.push(regs(&ops)),
                "ret" => has_ret = true,
                _ => {}
            }
        }
        let mirror = match (stp.first(), ldp.last()) {
            (Some(a), Some(b)) => a.len() >= 2 && a == b,
            _ => false,
        };
        if stp.len() < 6 || ldp.len() < 6 || !has_ret || !mirror {
            bad.push(format!(
                "{addr}: stp={} ldp={} ret={has_ret} mirror={mirror}",
                stp.len(),
                ldp.len()
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "有 RuntimeCallStub 名字无法从反汇编复核出「保存全部寄存器/逆序恢复」形状：{bad:?}"
    );
    println!(
        "runtime stub 命名可复核: {} 条全部满足 stp≥6 / ldp≥6 / ret / 首末镜像",
        named.len()
    );
    let _ = std::fs::remove_dir_all(&out);
}
