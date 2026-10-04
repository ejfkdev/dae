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

#[cfg(feature = "asm")] // 只有 progressive_cli 用它
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

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

#[cfg(feature = "asm")]  // 只有 progressive_cli 用它，而那条门禁本身是 asm-only
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

// 这条门禁整个建立在反编译器之上（`--decompile` + 读 `dart/` 目录），
// 而 `dart/` 只在 `asm` feature 下才会产出 ⇒ 无 capstone 的构建里它必然失败
// （`dart/ 目录: NotFound`）。此前没 gate，是因为 `cargo test --no-default-features`
// 根本**编译不过**（另两个测试文件直接引用了 `dae::decompiler`），失败被编译错误挡住了；
// 编译修好之后它就暴露出来。同文件其余三条门禁不依赖反编译器，照常两种配置都跑。
#[cfg(feature = "asm")]
#[test]
fn progressive_cli() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(sample) = corpus(root) else {
        skip_or_fail("progressive_cli: 无语料（先跑 testing/decompiler_corpus/build.sh）——跳过");
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

/// 帮助信息的形态门禁。**不需要语料**（帮助与快照无关），所以缺语料的检出里它照样跑——
/// 这正是它必须独立于 `progressive_cli` 的原因：那条整段挂在语料存在性上。
///
/// 钉住四件事：
/// 1. `dae`（无参数）、`dae -h`、`dae --help`、`dae help` 四种形态输出**逐字节相同**、退出码 0。
///    无参数曾经是「打印帮助但退出码 2」，而它并不是一个失败的调用。
/// 2. 每条命令的 `dae <cmd> -h`、`dae <cmd> --help`、`dae help <cmd>` 三种形态**逐字节相同**、
///    退出码 0，且**不需要位置参数**。第 2 条曾经对全部 22 条命令都是坏的：clap 的必填位置
///    参数校验发生在解析阶段、早于 handler，于是 `dae libs -h` 先撞上「required arguments
///    were not provided」而以 2 退出。而当时唯一的门禁跑的是 `dae help <cmd>`——它没有必填
///    位置参数、是好的，所以缺陷整整一个版本没被发现（`scripts/cmp_cli.sh` 的注释写着
///    「每条命令的 -h」而代码跑的是 `help "$c"`）。
/// 3. 顶层帮助**必须逐条列出全部子命令**。
/// 4. `dae help <不存在的命令>` 是用法错误（退出码 2），不是「退回打印整份指南并返回 0」。
#[test]
fn help_is_consistent_and_lists_every_command() {
    let bin = env!("CARGO_BIN_EXE_dae");
    // 命令清单写死在这里：新增命令而忘了写进帮助时，第 3 条断言会失败。
    const CMDS: [&str; 22] = [
        "export", "info", "libs", "classes", "functions", "strings", "fields", "largest", "pp",
        "objs", "stubs", "members", "callers", "callees", "findrefs", "disasm", "getclass",
        "getmethod", "getlib", "decompile", "help", "version",
    ];
    let out = |args: &[&str], env: Option<(&str, &str)>| -> (String, i32) {
        let mut c = Command::new(bin);
        c.args(args);
        if let Some((k, v)) = env {
            c.env(k, v);
        }
        let o = c.output().expect("启动 dae 失败");
        (
            String::from_utf8_lossy(&o.stdout).to_string(),
            o.status.code().unwrap_or(-1),
        )
    };

    for lang in [None, Some(("DAE_LANG", "zh"))] {
        let tag = lang.map(|(_, v)| v).unwrap_or("en");

        // 1) 顶层四种形态逐字节相同
        let (want, rc) = out(&["help"], lang);
        assert_eq!(rc, 0, "[{tag}] `dae help` 退出码应是 0");
        for form in [&[""][..], &["-h"][..], &["--help"][..]] {
            let args: Vec<&str> = form.iter().filter(|a| !a.is_empty()).copied().collect();
            let (got, rc) = out(&args, lang);
            assert_eq!(rc, 0, "[{tag}] `dae {}` 退出码应是 0", args.join(" "));
            assert_eq!(
                got, want,
                "[{tag}] `dae {}` 与 `dae help` 的输出必须逐字节相同（同一份文档只能有一处）",
                args.join(" ")
            );
        }
        assert!(
            want.lines().count() >= 60,
            "[{tag}] 顶层帮助只有 {} 行，大概没渲染出来",
            want.lines().count()
        );

        // 3) 顶层帮助逐条列出全部子命令
        for c in CMDS {
            assert!(
                want.contains(&format!("dae {c}")) || want.contains(&format!("dae {c} ")),
                "[{tag}] 顶层帮助没有列出子命令 `{c}`"
            );
        }

        // 2) 每条命令的三种形态逐字节相同、且不需要位置参数
        for c in CMDS {
            let (want, rc) = out(&["help", c], lang);
            assert_eq!(rc, 0, "[{tag}] `dae help {c}` 退出码应是 0");
            assert!(
                want.lines().count() >= 3,
                "[{tag}] `dae help {c}` 只有 {} 行，help_for 大概没覆盖到它",
                want.lines().count()
            );
            for flag in ["-h", "--help"] {
                let (got, rc) = out(&[c, flag], lang);
                assert_eq!(
                    rc, 0,
                    "[{tag}] `dae {c} {flag}` 退出码应是 0（缺位置参数时也必须能出帮助）"
                );
                assert_eq!(got, want, "[{tag}] `dae {c} {flag}` 与 `dae help {c}` 输出必须相同");
            }
        }

        // 4) 未知命令名是用法错误
        let (got, rc) = out(&["help", "nosuchcommand"], lang);
        assert_eq!(rc, 2, "[{tag}] `dae help nosuchcommand` 应是用法错误 2，实际 {rc}");
        assert!(
            got.is_empty(),
            "[{tag}] 未知命令名不该往 stdout 打整份指南（那会把拼写错误藏起来）"
        );
    }

    // 帮助文本是**终端输出**，不是 Markdown：粗体标记与字面量 `\t` 都不会被渲染，
    // 只会变成噪声（实测曾有 33 行含 `**`、12 行把制表符印成两个字符 `\t`）。
    let (en, _) = out(&["help"], None);
    for c in CMDS {
        let (t, _) = out(&["help", c], None);
        assert!(!t.contains("**"), "`dae help {c}` 含 Markdown 粗体标记，终端不渲染");
        assert!(
            !t.contains("\\t"),
            "`dae help {c}` 含字面量 \\t（应写成「制表符分隔」并用逗号列举）"
        );
    }
    assert!(!en.contains("**"), "顶层帮助含 Markdown 粗体标记");
    assert!(!en.contains("\\t"), "顶层帮助含字面量 \\t");
}

/// README 里内嵌的命令表必须与 `dae help` 的 COMMANDS 一节**逐字节一致**。
///
/// 这条盯的是一类已经真实发生过的漂移：README 抄了一份命令表，改了帮助却忘了改 README。
/// 具体实例——v0.1.12 把 `stubs` 的假说法（"instruction-table entries with no Code object"）
/// 在四处改正，中文 README 改了、**英文 README 这一份副本漏了**，于是发布出去的文档里
/// 还留着一个已经定性为错误的说法。
///
/// 两份 README 各取「渐进式」小节后第一个围栏块；权威来源是 `dae help` 的输出本身。
#[test]
fn readme_command_table_matches_help() {
    let bin = env!("CARGO_BIN_EXE_dae");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    /// 取出帮助输出里 COMMANDS（中文「命令」）与 OPTIONS（中文「选项」）之间的那一段
    fn commands_section(text: &str, head: &str, tail: &str) -> Option<String> {
        let lines: Vec<&str> = text.lines().collect();
        let a = lines.iter().position(|l| l.trim() == head)?;
        let b = lines.iter().position(|l| l.trim() == tail)?;
        Some(lines[a + 1..b].join("\n").trim_matches('\n').to_string())
    }

    /// 取出 README 里指定小节后的第一个 ``` 围栏块
    fn fenced_block(md: &str, section: &str) -> Option<String> {
        let sec = md.get(md.find(section)?..)?;
        let mut it = sec.split("```");
        it.next()?; // 小节标题到第一个围栏之间的正文
        Some(it.next()?.trim_matches('\n').to_string())
    }

    for (readme, section, head, tail) in [
        ("README.md", "## Progressive mode", "COMMANDS", "OPTIONS"),
        ("README.zh.md", "## 渐进式", "命令", "选项"),
    ] {
        let path = root.join(readme);
        let Ok(md) = std::fs::read_to_string(&path) else { continue };
        let want = commands_section(
            &String::from_utf8_lossy(
                &Command::new(bin)
                    .arg("help")
                    .env("DAE_LANG", if head == "命令" { "zh" } else { "en" })
                    .output()
                    .expect("启动 dae 失败")
                    .stdout,
            ),
            head,
            tail,
        )
        .expect("`dae help` 输出里应有 COMMANDS/OPTIONS 分节标题");
        let got = fenced_block(&md, section)
            .unwrap_or_else(|| panic!("{readme} 里找不到 `{section}` 小节后的围栏块"));
        assert_eq!(
            got, want,
            "{readme} 内嵌的命令表与 `dae help` 的 {head} 一节不一致——\
             改了帮助就要同步这份副本（历史上英文 README 就曾漏改，留下一个已定性为错误的说法）"
        );
    }
}

/// pp.txt 的首行**不许**是一个编造出来的十六进制数。
///
/// 这一行曾经硬编码为 `0x10f000080`（从 Python 参考实现原样移植，而参考实现自己也写死）。
/// blutter 是真算的（`raw_addr - app.heap_base()`），dae 既没有 image 里 ObjectPool 的地址、
/// 也没有 heap_base，所以算不出来；实测那个常量对 macOS 与安卓、压缩与非压缩指针的产物
/// 印出同一个值。这条测试守住「算不出来就不编」——一旦有人把数字塞回去，它就失败。
#[test]
fn pp_header_is_not_fabricated() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(sample) = corpus(root) else {
        skip_or_fail("pp_header_is_not_fabricated: 无语料——跳过");
        return;
    };
    let bin = env!("CARGO_BIN_EXE_dae");
    let out = std::env::temp_dir().join("dae_pp_header_check");
    let _ = std::fs::remove_dir_all(&out);
    let (_, e, rc) = run(
        bin,
        &[sample.display().to_string().as_str(), out.display().to_string().as_str()],
    );
    assert_eq!(rc, 0, "全量导出应成功：{e}");
    let pp = out.join("text").join("pp.txt");
    assert!(pp.exists(), "应产出 text/pp.txt");
    let first = std::fs::read_to_string(&pp)
        .expect("读 pp.txt")
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    assert!(
        first.starts_with("pool heap offset:"),
        "pp.txt 首行应保持与 blutter 对齐的键名，实得：{first}"
    );
    let value = first.trim_start_matches("pool heap offset:").trim();
    assert!(
        !value.starts_with("0x"),
        "pp.txt 又出现了具体的 pool heap offset 数值（{value}）——dae 没有 image 布局也没有 \
         heap_base，算不出这个值；写死一个数字就是编造，请改回 `unavailable` 并说明缘由"
    );
    assert!(
        value.starts_with("unavailable"),
        "pool heap offset 应如实写成 unavailable，实得：{value}"
    );
}

/// 平台 profile 的 `register_aliases` 必须与 `registers` **自洽**。
///
/// ## 为什么需要这条
///
/// 三个 arm64 平台 profile 里同时写着 `registers.code_reg = "x24"` 和
/// `register_aliases["x23"] = "CODE_REG"`——**互相矛盾**，而且错的是别名那一边：
/// Dart SDK `runtime/vm/constants_arm64.h` 从 2.12.4 到 3.13.0 **每一版**都写
/// `const Register CODE_REG = R24;`，而 R23 只是 `kAbiPreservedCpuRegs` 里一个
/// **没有名字角色**的普通被保留寄存器。于是每一份 arm64 产物都把 x23 印成 `CODE_REG`、
/// 把真正的 CODE_REG（x24）印成裸 `r24`/`x24`（material_3_demo 实测 asm/ 里 1010 处、
/// dart/ 里 3014 处错标）。两个错误都来自被移植的 Python 参考实现
/// （`dart_aot_export.py` 同一行还写了 `"x18": "ARG2"`，而 `ARG2` 在**任何版本的
/// constants_arm64.h 里都不存在**；R18 的注释是「reserved on iOS, shadow call stack on
/// Fuchsia, TEB on Windows」，SDK 还明说「We rely on R18 not being touched by Dart
/// generated assembly or stubs at all」——实测产物里 x18/ARG2 出现 **0 次**，
/// 所以删掉它对输出是可证明的无操作）。
///
/// 这类矛盾能长期存活，是因为**没有任何检查把两张表对在一起看**：
/// `scripts/check_profiles.sh` 只管 SDK profile 的新鲜度，不碰平台 profile 的寄存器表。
///
/// ## 判据
///
/// 对每个 `registers` 里的角色：若它的名字（大写）出现在 `register_aliases` 的值里，
/// 那么 `registers` 给的物理寄存器**必须在**那些物理寄存器之中。
/// 用「在其中」而不是「恰好相等」，是因为一个角色可以有多个编码——
/// `sp` 就同时对应 `x15`（Dart 代码里的 SP）与 `x31`（硬件 SP 编码），两者都该印 `SP`。
///
/// 反向也查：任何被标成某角色名的物理寄存器，如果 `registers` 里有这个角色、
/// 却指向别的寄存器，就是本条要抓的矛盾。
///
/// 这条门禁**不吃语料**（只读仓库里被 include_str! 的那几份 JSON），所以任何检出里都会真跑。
#[test]
fn platform_register_aliases_are_self_consistent() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = root.join("profiles/platform");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("读不到 {}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    files.sort();
    assert!(
        files.len() >= 6,
        "只找到 {} 份平台 profile（期望 ≥6：macho/elf/pe × arm64/x64）——路径是不是错了？\
         这条门禁不吃语料，份数不对就说明它根本没在测东西",
        files.len()
    );
    let mut checked = 0usize;
    let mut arm64 = 0usize;
    for f in &files {
        let txt = std::fs::read_to_string(f).unwrap();
        // 走**发布用的那个解析器**（`parse_platform`，也就是 `include_str!` 进二进制的同一份数据
        // 与同一条反序列化路径），这样测的是产物真正用到的表，而不是文件里的字面 JSON。
        let pp = dae::profile::parse_platform(&txt)
            .unwrap_or_else(|e| panic!("{} 解析失败: {e}", f.display()));
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        let regs = &pp.registers;
        let al = &pp.register_aliases;
        if pp.arch == "arm64" {
            arm64 += 1;
        }
        // 角色名（大写）→ 被标成该名字的物理寄存器集合
        let mut by_role: std::collections::BTreeMap<String, Vec<String>> = Default::default();
        #[allow(clippy::implicit_clone)]
        for (phys, alias) in al {
            by_role.entry(alias.to_ascii_uppercase()).or_default().push(phys.clone());
        }
        for (role, p) in regs {
            let p = p.as_str();
            checked += 1;
            let key = role.to_ascii_uppercase();
            if let Some(who) = by_role.get(&key) {
                assert!(
                    who.iter().any(|x| x == p),
                    "{name}: registers.{role} = {p}，但 register_aliases 把 {key} 标在 {who:?} 上。\n\
                     两张表矛盾时，产物会用**别名表**渲染，于是寄存器被印成错的角色名。\n\
                     历史故障：三个 arm64 profile 都写 code_reg=x24 而别名把 CODE_REG 标在 x23；\n\
                     SDK constants_arm64.h（2.12.4–3.13.0 每一版）都是 `CODE_REG = R24`，\n\
                     R23 没有名字角色，所以错的是别名表。"
                );
            }
        }
        // 反向：别名表里出现的角色名，若 registers 有同名角色则上面已查；
        // 这里额外钉住「CODE_REG 必须标在 registers.code_reg 上」这一条最要命的，
        // 因为它是唯一被产物大量渲染、且曾经标错的那个。
        if let Some(cr) = regs.get("code_reg") {
            if by_role.contains_key("CODE_REG") {
                assert_eq!(
                    by_role["CODE_REG"],
                    vec![cr.to_string()],
                    "{name}: CODE_REG 别名必须恰好标在 registers.code_reg（{cr}）上"
                );
            }
        }
    }
    assert!(
        checked >= 20,
        "只比对了 {checked} 个 (profile, 角色) 对——太少，这条门禁等于没跑"
    );
    assert!(arm64 >= 3, "只看到 {arm64} 份 arm64 profile（期望 macho/elf/pe 三份）");
    println!(
        "平台寄存器别名自洽: {} 份 profile、{} 个 (profile, 角色) 对、其中 arm64 {} 份",
        files.len(),
        checked,
        arm64
    );
}

/// 压缩指针目标的 `DartThread` 必须补上 `heap_base`，且**只补一个、补在正确位置**。
///
/// ## 为什么这条比 stub 命名严重
///
/// `DartThread` 是**发给 IDA/r2 的结构体**。SDK `runtime/vm/thread.h` 里 `heap_base_` 是
/// `#if defined(DART_COMPRESSED_POINTERS)` 包着的条件字段，而且是 `Thread` 里唯一一个；
/// 压缩指针＝**每一个移动端 Flutter 产物**，所以不补就意味着从 `write_barrier_mask` 之后
/// 所有字段整体错位 8 字节，用户在 IDA 里按结构体读线程字段会全错。
/// 仓库里 48 份头文件对此不一致（2.13.4–2.19.6 已含 `heap_base`，其余不含），
/// 所以规则是「目标压缩 **且** 头里没有」才插——已含的必须**原样不动**（幂等）。
///
/// ## 三处代码实测把这条钉死了（dart 3.3.4 / Reqable，压缩指针）
///
/// 补完之后结构头给出的偏移与产物里的代码**逐一对上**：
/// `stack_limit` = 0x38（`ldr x16,[x26,#0x38]` + `cmp SP` + `b.ls` 就是 CheckStackOverflow）、
/// `top` = **0x50**（胖分配 stub 的 `ldp x0,x2,[x26,#0x50]` 与 `str x0,[x26,#0x50]`）、
/// `write_barrier_entry_point` = **0x1e8**（屏障子 stub 的 `ldr x30,[x26,#0x1e8]`）。
/// 补之前 `top` 会算成 0x48、屏障字段会算成 `array_write_barrier_entry_point`——
/// 后者正是当时对 Reqable/飞书发布出 `ArrayWriteBarrierStub_*` 这个**错名**的原因。
#[test]
fn dart_thread_struct_gets_heap_base_only_for_compressed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = root.join("profiles/struct");
    let mut vers: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("读不到 {}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    vers.sort();
    assert!(vers.len() >= 20, "只找到 {} 个 struct 版本目录（期望 ≥20）", vers.len());
    let fields = |txt: &str| -> Vec<String> {
        txt.lines()
            .skip(1)
            .take_while(|l| !l.trim_start().starts_with('}'))
            .filter_map(|l| l.trim().trim_end_matches(';').split_whitespace().last().map(String::from))
            .collect()
    };
    let (mut n, mut had, mut inserted) = (0usize, 0usize, 0usize);
    for v in &vers {
        for arch in ["arm64", "x64"] {
            let p = v.join(format!("dart_struct-{arch}.h"));
            let Ok(src) = std::fs::read_to_string(&p) else { continue };
            n += 1;
            let base = fields(&src);
            assert!(
                base.iter().filter(|x| *x == "write_barrier_mask").count() == 1,
                "{}: 应恰有一个 write_barrier_mask",
                p.display()
            );
            let had_hb = base.iter().any(|x| x == "heap_base");
            // 非压缩：必须原样
            assert_eq!(
                dae::export::struct_hdr::with_heap_base(&src, false),
                src,
                "{}: 非压缩目标不该改动结构头",
                p.display()
            );
            let out = dae::export::struct_hdr::with_heap_base(&src, true);
            let got = fields(&out);
            assert_eq!(
                got.iter().filter(|x| *x == "heap_base").count(),
                1,
                "{}: 压缩目标必须恰好有一个 heap_base（原来{}）",
                p.display(),
                if had_hb { "就有" } else { "没有" }
            );
            // 位置：紧跟 write_barrier_mask
            let wm = got.iter().position(|x| x == "write_barrier_mask").unwrap();
            let hb = got.iter().position(|x| x == "heap_base").unwrap();
            assert_eq!(
                hb,
                wm + 1,
                "{}: heap_base 必须紧跟 write_barrier_mask（wm={wm} hb={hb}）",
                p.display()
            );
            // top 必须因此后移 8 字节（1 个字段）——除非头里本来就有 heap_base
            let top_before = base.iter().position(|x| x == "top").expect("应有 top");
            let top_after = got.iter().position(|x| x == "top").expect("应有 top");
            if had_hb {
                had += 1;
                assert_eq!(out, src, "{}: 头里已有 heap_base 就必须幂等", p.display());
                assert_eq!(top_after, top_before);
            } else {
                inserted += 1;
                assert_eq!(
                    top_after,
                    top_before + 1,
                    "{}: 插入 heap_base 后 top 应后移一个字段（{} -> {}）",
                    p.display(),
                    top_before * 8,
                    top_after * 8
                );
            }
            // 其余字段顺序不变
            let strip = |v: &Vec<String>| -> Vec<String> {
                v.iter().filter(|x| *x != "heap_base").cloned().collect()
            };
            assert_eq!(strip(&base), strip(&got), "{}: 除 heap_base 外字段顺序不得改变", p.display());
        }
    }
    assert!(n >= 40, "只检查了 {n} 份结构头（期望 ≥40：20+ 版本 × 2 架构）");
    assert!(inserted >= 20, "只有 {inserted} 份需要插入 heap_base——预期约一半，数字太小可能是解析没生效");
    println!(
        "DartThread 压缩变体: {n} 份结构头，{inserted} 份需插入 heap_base、{had} 份本就有（幂等）"
    );
}
