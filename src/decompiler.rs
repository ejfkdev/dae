//! 伪 Dart 反编译（第一版：lift → CFG → 发射）。
//!
//! 流水线对齐同族工具的分层（ddc/flutterdec 都是「机器相关前端 → 机器无关结构化 → 发射」）：
//! 1. **lift**：反汇编 → 逐条 IR（赋值/调用/分支/返回/池加载；认不出的原样保留为 `Other`，
//!    不猜语义）；
//! 2. **cfg**：按分支目标切基本块、连边（含条件分支的两个后继）；
//! 3. **emit**：每个函数发射伪 Dart——直线语句 + 基本块标签 + `goto`（Dart 没有 goto，
//!    所以这一版是**伪代码**而非可编译 Dart；结构化 if/while 是下一阶段）。
//!
//! 明确不做的事：不编造类型、不编造间接调用目标、不省略认不出的指令（`Other` 原样带出）。

use crate::analyzer::{Analyzer, FieldRow, LibGroups};
use crate::engine::snapshot::PoolKind;
use crate::engine::restore::scrub_name;
use capstone::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

pub struct DecompileStats {
    pub funcs: usize,
    pub blocks: usize,
    pub stmts: usize,
    pub structured: usize,
    pub fallback: usize,
    /// lift 认不出的指令行数（`// unmapped:`）——**质量主轴**：越小越好
    pub unmapped: usize,
    /// 直接调用总数 / 其中解析出名字的个数
    pub calls: usize,
    pub calls_named: usize,
}

// ---------------------------------------------------------------- lift

/// 一条 IR 语句的来源表达式
#[derive(Clone, Debug)]
enum Expr {
    /// 寄存器
    Reg(String),
    /// 立即数
    Imm(i64),
    /// 对象池条目（pp 索引）
    Pool(u64),
    /// 内存读取（操作数原文，不解析语义）
    Mem(String),
    /// 已渲染好的表达式文本，原样输出（嵌套落地用）
    Text(String),
}

impl Expr {
    fn text(&self, rl: &Roles) -> String {
        match self {
            Expr::Reg(r) => r.clone(),
            Expr::Imm(v) => format!("{v}"),
            Expr::Pool(i) => format!("pp[0x{i:x}]"),
            Expr::Mem(m) => mem_read(rl, m),
            Expr::Text(x) => x.clone(),
        }
    }
}

#[derive(Clone, Debug)]
enum Op {
    Assign { dst: String, src: Expr },
    /// 直接调用（target = 目标地址）；间接调用 target = None、callee 为操作数原文。
    /// `resolved` = 目标地址对应的函数名（来自 Code 对象的库/类/方法名）。
    Call {
        dst: Option<String>,
        target: Option<u64>,
        callee: String,
        resolved: Option<String>,
    },
    /// cond = None 表示无条件跳转
    Branch { cond: Option<String>, target: u64 },
    Return { value: Option<String> },
    /// 写内存：`mem(target) = value`
    Store { target: String, value: String },
    /// `brk #n`：陷阱/不可达（终止符）
    Abort(i64),
    /// `cmp`/`tst`：只为保留地址占用一个语句位，不渲染（条件已并入紧随的分支）
    Cmp,
    /// 间接跳转（arm64 `br x17` = 跳转表分发）：终止符，没有落空边
    IndirectJump(String),
    /// 用占位函数表达的机器操作（`xchg`/`idiv`/`sbc`/`fcvtms`…）：渲染成 `helper(args);`。
    /// 与 `Other` 的区别：这些指令**认得出来**，只是没有 Dart 层的精确语义，
    /// 写成占位调用比留成 `// unmapped:` 更接近实际（也便于 grep）。
    Helper(String),
    /// 成对读（`ldp d1, d2, [base, disp]`）：Dart 没有元组赋值（`a, b = mem(...)` 不是
    /// 合法语法），渲染成 `memRead2(base, disp, d1, d2);`——语义是"读两个字进这两个寄存器"。
    PairLoad { base: String, disp: String, d1: String, d2: String },
    /// 认不出来的指令：原文保留
    Other(String),
    /// **认得出来**但无语义信息的指令：帧保存/恢复（stp/ldp 到栈）、屏障（dmb/isb）。
    /// 与 Other 的区别是它不降低可读性指标——产物里以 `// frame:` / `// barrier:`
    /// 注释形式保留原文，可 grep、但不冒充数据流语句。
    Note(String),
}

#[derive(Clone, Debug)]
struct Stmt {
    addr: u64,
    op: Op,
}

/// 反汇编一个函数体，返回 (语句, 反汇编全文用于注释)。
///
/// 有状态的两件事：
/// 1. `cmp`/`test` 的结果喂给紧随的条件跳转，拼成真条件（`if (rdx < 2)` 而不是 `if (jl)`）；
///    没有可比对象时如实退回 mnemonic——不编条件。
/// 2. 寄存器名统一替换成框架名（FP/SP/THR/PP…），内存操作数内部也替换。
fn lift(
    cs: &Capstone,
    rl: &Roles,
    code: &[u8],
    base: u64,
    is_arm64: bool,
    names: &BTreeMap<u64, String>,
) -> (Vec<Stmt>, String) {
    // `Roles` 由调用方传入，**不在这里构建**：`roles()` 会调 `pool_map()` 重建整张对象池
    // 映射表（Reqable.app 有 122 064 条），而 lift 是每函数调一次的——曾经每个函数都重建
    // 一遍池表，material_3_demo 15 082 个函数上光这一步就吃掉 100.2s（占 render 的 94%）。
    let mut out = Vec::new();
    let mut raw = String::new();
    let mut last_cmp: Option<(String, String)> = None;
    let Ok(insns) = cs.disasm_all(code, base) else {
        return (out, raw);
    };
    // 每行注释约 40 字节；不预留就会随指令数反复扩容
    raw.reserve(insns.len() * 40);
    for ins in insns.iter() {
        let mnem = ins.mnemonic().unwrap_or("").to_string();
        let ops_masked = mask_regs(rl, ins.op_str().unwrap_or(""));
        let addr = ins.address();
        let _ = writeln!(raw, "  {addr:#x}: {mnem} {ops_masked}");
        // IR 用**去掉 `#`** 的操作数：`#` 只是汇编的立即数标记，`mem(x2, #0x3f)`、
        // `SP - #8`、`1 << #0` 这类残留会让 Dart 解析器报 expected_token。
        // 反汇编注释块（raw）保留原样，便于与 asm/ 产物逐字对照。
        let ops = ops_masked.replace('#', "");
        // x86 的浮点比较是 `comisd`/`ucomisd`（SSE），arm64 是 `fcmp`——都不产出目标寄存器，
        // 只设标志位，所以与 `cmp` 同一处理：不出语句、只记下 (a, b) 供紧随的分支折叠。
        if matches!(
            mnem.as_str(),
            "cmp" | "cmn"
                | "tst"
                | "test"
                | "fcmp"
                | "fcmpe"
                | "comisd"
                | "comiss"
                | "ucomisd"
                | "ucomiss"
        ) {
            let mut it = ops.split(',');
            let a = it.next().unwrap_or("").trim().to_string();
            let b_raw = it.next().unwrap_or("").trim().to_string();
            // 第三段是移位修饰（`lsr #32` 去掉 `#` 后是 `lsr 32`）。**丢掉它会让操作数
            // 错一个数量级**：Dart 写屏障的快路径判定就是 `tst BARRIER, HEAP, lsr #32`。
            let shift = it.next().unwrap_or("").trim().to_string();
            // `test`/`tst` 是**位测试**：算的是 `a & b` 并据此设标志位，所以
            // `tst a, b; b.eq` 的真值是 `(a & b) == 0`，**不是 `a == b`**。
            // 原来这里只在 `b == a` 时特殊处理（`tst x,x` → `x == 0`），其余情况把
            // `(a, b)` 原样交给 fold_cond，于是 `b.eq` 渲染成 `a == b` —— 运行期两个
            // 寄存器几乎不可能全等，写屏障的快/慢路径就此**语义反转**（伪码恒走 else
            // 去调用屏障 stub）。这不是 condFlag 那种诚实占位，是给出了错的具体表达式。
            // 实测 Reqable：`if (X == HEAP)` 形态 **436 行**，对应 458 条
            // `tst …, HEAP, lsr #32`；x86 的 `test eax, 0x20` + `je` 同样中招。
            let (a, b) = if matches!(mnem.as_str(), "test" | "tst") {
                if b_raw == a {
                    // tst x, x ⇔ x == 0（保持原有行为）
                    (a.clone(), "0".to_string())
                } else {
                    let mut bb = b_raw.clone();
                    // 应用移位修饰；只认得这四种，认不出来就**不猜**、原样保留
                    let mut sp = shift.split_whitespace();
                    match (sp.next(), sp.next()) {
                        (Some("lsr"), Some(n)) => bb = format!("({bb} >> {n})"),
                        (Some("lsl"), Some(n)) => bb = format!("({bb} << {n})"),
                        (Some("asr"), Some(n)) => bb = format!("({bb} >> {n}) /* arithmetic */"),
                        (Some("ror"), Some(n)) => bb = format!("ror({bb}, {n})"),
                        _ => {}
                    }
                    (format!("({a} & {bb})"), "0".to_string())
                }
            } else {
                (a, b_raw)
            };
            last_cmp = Some((a, b));
            // 比较不单独出**语句行**（紧随的条件分支已经把它表达成 `if (a op b)`），
            // 但必须保留下**地址**：`tbz ...; cmp; b.eq` 这类代码的分支目标常常正落在
            // 比较指令上，丢掉它的地址就没有块起点，分支解析不了（曾使 895 个函数
            // 退化成不可结构化）。render_op 对 Cmp 返回 None，故产物里仍不出现。
            out.push(Stmt { addr, op: Op::Cmp });
            continue;
        }
        let s = match lift_one(rl, is_arm64, &mnem, &ops, addr) {
            // csel/cset：条件码先换成 condFlag("cc")，再尝试用上一条 cmp 折成真条件。
            // `cset`/`csetm` 必须一起列进来：它们是 `csinc`/`csinv` 的别名形式，
            // 同样依赖上一条 `cmp` 才有语义。漏掉它们的后果不是「少个名字」而是
            // **语句整条消失**——见 `nest_block` 里 `Expr::Text` 的注释。
            // 实测 stress2 样例 `Level.get_tag`：`int get rank => this == Level.low ? 0 : 1`
            // 被 AOT 内联成 `cmp x1, <Level.low>; cset x2, ne`，两条都不出语句，
            // 产物里只剩 `x2 = x2 << 1`，而 x2 还是上面 `x2 = 4`（插值数组长度）的残值。
            Op::Assign { dst, src: Expr::Text(t) }
                if matches!(
                    mnem.as_str(),
                    "csel" | "csinc" | "cset" | "csetm" | "cinc" | "cinv" | "cneg"
                ) || (!is_arm64 && (is_x86_setcc(&mnem).is_some() || is_x86_cmov(&mnem).is_some()))
                =>
            {
                if let (Some((a, b)), Some(cc)) = (&last_cmp, sel_cc(&t)) {
                    // fold_cond 的表是按跳转助记符（`b.eq`/`je`）写的，条件码要先补前缀；
                    // 前缀按 ISA 取：arm64 是 `b.`，x86 是 `j`（`setne` ↔ `jne`）。
                    // **折不出来时它原样返回**，那就必须保留 condFlag(...)，不能把裸
                    // `eq` 塞回去（`(eq) ? a : b` 过不了分析）。
                    let as_branch = if is_arm64 {
                        format!("b.{cc}")
                    } else {
                        format!("j{cc}")
                    };
                    let folded = fold_cond(&as_branch, &Some((a.clone(), b.clone())));
                    if folded == as_branch {
                        Op::Assign { dst, src: Expr::Text(t) }
                    } else {
                        Op::Assign {
                            dst,
                            src: Expr::Text(t.replace(&sel_cond(cc), &folded)),
                        }
                    }
                } else {
                    Op::Assign { dst, src: Expr::Text(t) }
                }
            }
            Op::Branch { cond: Some(c), target } => {
                // 条件已被这次分支消费：不清空的话，隔着若干条不设标志位的指令后
                // 再来一个 `b.eq` 会错误复用**上一条**比较（拼出假条件）。
                //
                // ⚠️ 只有「lift 时如实记下助记符」的分支才需要折叠（`b.eq`/`je` 那一路，
                // 见下面的 `mnem.starts_with("b.")` 分支）。`cbz`/`cbnz`/`tbz`/`tbnz`
                // **自带条件**，lift 时已经生成完整的 Dart 布尔表达式（`x2 != 0`、
                // `w1 & (1 << 0) != 0`）；把它们再喂给 `fold_cond` 会因为匹配不到助记符而
                // 落到兜底分支 `condFlag("{mnem}")`，于是合法表达式被包成
                // `condFlag("x2 != 0")` —— 信息还在，但读的人得自己把引号里的东西抄出来。
                // 实测 material_3_demo 上这类占位有 14 886 处，其中 **84.3%（12 550）的
                // 参数本身就是合法布尔表达式**，只有 `vc`/`vs`/`eq`/`ne` 那 15.7% 是真需要占位的。
                //
                // 判据用「含不含空格」：助记符（`b.eq`/`jne`/`jle`…）从不含空格，而两条
                // 自带条件的生成式（`"{a} {op} 0"` 与 `"{} & (1 << {}) {op} 0"`）一定含空格。
                // 不认得的裸标识符仍走 fold_cond → condFlag，避免把 `if (eq)` 这种
                // 过不了分析的写法放进产物。
                // 判据是「**长得像不像助记符**」，不是「含不含空格」。
                //
                // 原来写的是 `c.contains(' ')`：助记符（`b.eq`/`jne`）从不含空格，而
                // lift 生成的自带条件表达式（`x2 != 0`、`w1 & (1 << 4) != 0`）一定含空格。
                // 但还原成语义判断后这个代理判据就失效了——`isSmi(x0)` **不含空格**，
                // 于是被当成助记符送进 fold_cond，匹配不到就落到兜底
                // `condFlag("isSmi(x0)")`：信息躲进字符串字面量，**比还原前更糟**
                // （实测 Reqable 上 1232 处 `& (1 << 0)` 形态确实归零了，但全都变成了
                // `condFlag("isSmi(...)")`）。
                //
                // 直接判形状：助记符只由小写字母和 `.` 组成（`b.eq`/`b.ls`/`jne`/`jle`），
                // 任何含大写、括号、运算符或空格的都已经不是助记符。
                let is_mnem = !c.is_empty()
                    && c.chars()
                        .all(|ch| ch.is_ascii_lowercase() || ch == '.');
                let cond = Some(if is_mnem {
                    fold_cond(&c, &last_cmp)
                } else {
                    c.clone()
                });
                last_cmp = None;
                Op::Branch { cond, target }
            }
            // 直接调用：用函数名表把目标地址换成名字（可读性的关键一步）
            Op::Call { dst, target: Some(t), callee, resolved: None } => Op::Call {
                dst,
                target: Some(t),
                callee,
                resolved: names.get(&t).cloned(),
            },
            // 设标志位的算术指令会作废先前的比较结果
            Op::Assign { .. }
                if matches!(
                    mnem.as_str(),
                    "adds" | "subs" | "ands" | "bics" | "negs" | "adcs" | "sbcs"
                ) =>
            {
                last_cmp = None;
                lift_one(rl, is_arm64, &mnem, &ops, addr)
            }
            other => other,
        };
        // arm64：写 32 位的 `wN` 会把 `xN` 的高 32 位**清零**，两者是同一个物理寄存器的
        // 两个视图。但产物里 `wN` 与 `xN` 是两个独立的 Dart 变量，于是「先写 wN、后读 xN」
        // 读到的是 xN 的**旧值**（或从未赋值的值）。实测 material_3_demo：这样的读点
        // **3 590 处、波及 1 135 个函数（7.6%）**。stress3 样例的 `hashBytes` 里
        // `w4 = w1 << 5; w6 = w1 >> 27;` 之后 `(x4 | x6)` 读的就是两个陈旧变量——
        // 而那正是源码的 rotate `((h << 5) | (h >> 27))`。
        //
        // 补一条别名赋值把两个视图接上：`xN = wN & 0xffffffff`。
        // ⚠️ 不能简单把 `wN` 改名成 `xN`——`w4 = w1 + w2` 的真值是
        // `(w1 + w2) mod 2^32`，改名就丢了截断；也不能只改写入端，那样后续**读** `wN`
        // 的地方会变成未定义变量。加一条别名语句两头都保住，且 `nest_block` 会把它
        // 折进后面的表达式，不额外增加可读性负担。
        let walias: Option<(String, String)> = if is_arm64 {
            match &s {
                Op::Assign { dst, .. } => dst.strip_prefix('w').and_then(|n| {
                    (!n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
                        .then(|| (format!("x{n}"), dst.clone()))
                }),
                _ => None,
            }
        } else {
            None
        };
        out.push(Stmt { addr, op: s });
        if let Some((xd, wn)) = walias {
            out.push(Stmt {
                addr,
                op: Op::Assign {
                    dst: xd,
                    src: Expr::Text(format!("{wn} & 0xffffffff")),
                },
            });
        }
    }
    (out, raw)
}

/// x86 `cmov<cc>` 的条件后缀 → 条件码本身。与 [`is_x86_setcc`] 共用同一张白名单：
/// 两者的条件编码完全一致，且都只收 `fold_cond` 真能处理的，认不出来就不接管
/// （继续 `// unmapped`，绝不编 `condFlag("j…")` 这种名字）。
fn is_x86_cmov(mnem: &str) -> Option<&'static str> {
    let cc = mnem.strip_prefix("cmov")?;
    is_x86_setcc(&format!("set{cc}"))
}

/// x86 `setcc` 的条件后缀白名单 → 条件码本身。
///
/// 只收 `fold_cond` 里**确实有对应跳转助记符**的那些（`setne` ↔ `jne`、`setae` ↔ `jae`…），
/// 这样折出来的条件一定是真比较或明确的 `condFlag("…")`，不会出现 `condFlag("jxyz")`
/// 这种编造名。不在表里的 `set…` 一律不接管，保持 unmapped 注释。
fn is_x86_setcc(mnem: &str) -> Option<&'static str> {
    const CC: [&str; 26] = [
        "e", "z", "ne", "nz", "l", "b", "nae", "le", "be", "na", "g", "a", "nbe", "ge", "ae",
        "nb", "s", "ns", "o", "no", "c", "nc", "p", "np", "pe", "po",
    ];
    let cc = mnem.strip_prefix("set")?;
    CC.into_iter().find(|c| *c == cc)
}

/// 条件选择（csel）的条件码 → Dart 可达的布尔表达式。
/// 认得的条件码（eq/ne/lt/gt…）写成 `condFlag("eq")`；调用方若能从上一条比较折出
/// 真条件，会先用 `fold_cond` 替换掉它。返回值类型是 bool（占位函数声明如此），
/// 这样 `(cond) ? a : b` 才过得了分析。
fn sel_cond(cc: &str) -> String {
    format!("condFlag(\"{cc}\")")
}

/// 从 `condFlag("hi")` 里取回条件码
fn sel_cc(rendered: &str) -> Option<&str> {
    let i = rendered.find("condFlag(\"")? + "condFlag(\"".len();
    let rest = &rendered[i..];
    let j = rest.find('"')?;
    Some(&rest[..j])
}

/// 条件跳转 + 上一条比较 → 真条件表达式；拼不出来时保留 mnemonic（不猜）。
fn fold_cond(mnem: &str, last: &Option<(String, String)>) -> String {
    // 纯**标志位**条件（进位/溢出/奇偶…）：`adds r0, r3, r3` + `b.vc` 这类。它们不是
    // 比较，Dart 层表达不出来，但必须**明确说这是 CPU 标志**，而不是把助记符原文
    // （`b.vc`）塞进 `if (...)`——那会编译得过、语义却什么都不是（实测一个自编程序里
    // 有 335 处 `if (b.vc)`）。`condFlag("vc")` 是前导里已声明的占位。
    let flag_only = |cc: &str| format!("condFlag(\"{cc}\")");
    let op = match mnem {
        // arm64：其余条件码统一走 condFlag
        "b.eq" | "b.ne" | "b.lt" | "b.le" | "b.gt" | "b.ge" | "b.hi" | "b.hs" | "b.lo" | "b.ls"
        | "b.mi" | "b.pl" => match mnem {
            "b.eq" => "==",
            "b.ne" => "!=",
            "b.lt" => "<",
            "b.le" => "<=",
            "b.gt" => ">",
            "b.ge" => ">=",
            "b.hi" => ">",
            "b.hs" => ">=",
            "b.lo" => "<",
            "b.ls" => "<=",
            "b.mi" => "<",
            _ => ">=",
        },
        "b.vs" | "b.vc" | "b.cs" | "b.cc" => return flag_only(&mnem[2..]),
        // x86：同上
        "je" | "jz" => "==",
        "jne" | "jnz" => "!=",
        "jl" | "jb" | "jnae" => "<",
        "jle" | "jbe" | "jna" => "<=",
        "jg" | "ja" | "jnbe" => ">",
        "jge" | "jae" | "jnb" => ">=",
        "js" => "<",
        "jns" => ">=",
        "jo" | "jno" | "jc" | "jnc" | "jp" | "jnp" | "jpe" | "jpo" => {
            return flag_only(&mnem[1..])
        }
        _ => return format!("condFlag(\"{mnem}\")"),
    };
    match last {
        Some((a, b)) => format!("{a} {op} {b}"),
        // 没有可折的比较：不能把助记符原文当表达式，明确标成标志位
        None => {
            let cc = mnem.trim_start_matches('b').trim_start_matches('.');
            flag_only(cc)
        }
    }
}

/// 把寄存器名替换成框架名（PP/THR/SP/FP/LR），内存操作数内部同样替换。
/// 构建寄存器别名表，并把**级联**解析成每个 token 的最终值。
///
/// 原先 `mask_regs` 每条指令都重建这张表（克隆 aliases + 追加 pp/thr + 10 个硬编码项、
/// 再按 key 长度降序稳定排序），然后对每个 pair 各做一次「分配新 String + 全文扫描」的
/// `replace_word`——约 100 万条指令 × 20 个 pair = 两千万次分配与扫描。表对整个 run 是常量，
/// 所以只建一次。
///
/// 单遍查表**不能**直接替代顺序替换：替换会级联。实测 arm64 profile 的 aliases 里有
/// `x29→fp`、`x30→lr`（小写），而硬编码表后面还有 `fp→FP`、`lr→LR`；按长度降序稳定排序后
/// 3 字符键先跑、2 字符键后跑，于是 `x29 → fp → FP`。所以这里按**原有的 pair 顺序**
/// 模拟整条链，把每个键解析到终值，单遍查表才与逐 pair 替换严格等价。
fn build_mask_map(
    aliases: &std::collections::HashMap<String, String>,
    pp: &str,
    thr: &str,
) -> std::collections::HashMap<String, String> {
    let mut pairs: Vec<(String, String)> = aliases
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    pairs.push((pp.to_string(), "PP".into()));
    pairs.push((thr.to_string(), "THR".into()));
    for (k, v) in [
        ("x29", "FP"),
        ("x30", "LR"),
        ("rbp", "FP"),
        ("rsp", "SP"),
        ("esp", "SP"),
        ("ebp", "FP"),
        // arm64 的小写助记名（capstone arm64 出 `sp`/`fp`/`lr`）
        ("sp", "SP"),
        ("fp", "FP"),
        ("lr", "LR"),
    ] {
        pairs.push((k.to_string(), v.to_string()));
    }
    // 别名表按 key 长度倒序：短名先换会把 `x15` 里的 `x1` 之类误伤
    // （历史上 arm64 的 `sp` 因此显示成裸 `x15`）。sort_by_key 是稳定排序，
    // 等长的键保持插入顺序——这与旧实现一致，也是级联结果一致的前提。
    pairs.sort_by_key(|a| std::cmp::Reverse(a.0.len()));

    let mut map = std::collections::HashMap::with_capacity(pairs.len() * 2);
    for (k, _) in &pairs {
        if map.contains_key(k) {
            continue;
        }
        // 按 pair 顺序模拟：当前值等于某个键就被替换，直到走完全部 pair
        let mut cur = k.clone();
        for (pk, pv) in &pairs {
            if &cur == pk {
                cur = pv.clone();
            }
        }
        map.insert(k.clone(), cur);
    }
    map
}

fn mask_regs(rl: &Roles, ops: &str) -> String {
    // 单遍扫描：按 `replace_word` 的词边界定义（[A-Za-z0-9_] 的极大串）切出 token，
    // 查预解析好的别名表。等价于旧的「按 key 长度降序逐 pair 做 replace_word」——
    // 表里存的就是每个 token 走完全部 pair 后的终值（见 `build_mask_map`）。
    let b = ops.as_bytes();
    let mut out = String::with_capacity(ops.len() + 8);
    let mut i = 0usize;
    // 已拷贝到的位置：分隔符整段用 push_str 搬，而不是逐字节 push。
    let mut last = 0usize;
    while i < b.len() {
        if is_word_byte(b[i]) {
            let start = i;
            while i < b.len() && is_word_byte(b[i]) {
                i += 1;
            }
            if let Some(v) = rl.mask_map.get(&ops[start..i]) {
                out.push_str(&ops[last..start]);
                out.push_str(v);
                last = i;
            }
        } else {
            i += 1;
        }
    }
    out.push_str(&ops[last..]);
    out
}

/// `replace_word` / `mask_regs` 共用的词边界判据：字母数字与下划线。
#[inline]
fn is_word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// 按「词边界」替换（前后不能是字母数字），避免 `r1` 命中 `r14`。
fn replace_word(s: &str, from: &str, to: &str) -> String {
    let b = s.as_bytes();
    let fb = from.as_bytes();
    let mut out = String::with_capacity(s.len() + to.len());
    let mut i = 0usize;
    // 已拷贝到的位置：整段用 push_str 搬，而不是逐字节 `push(b[i] as char)`——
    // 后者每个字节都要做一次 char 转换 + UTF-8 编码，在百万条语句量级上是主要开销。
    let mut last = 0usize;
    while i < s.len() {
        if b[i..].starts_with(fb) && (i == 0 || !is_word_byte(b[i - 1])) {
            let j = i + from.len();
            if j >= s.len() || !is_word_byte(b[j]) {
                out.push_str(&s[last..i]);
                out.push_str(to);
                i = j;
                last = j;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&s[last..]);
    out
}

/// 反汇编注释块里一行的指令地址（`  0x49e260: csetm x0, eq` → Some(0x49e260)）。
/// 解析不出来返回 None——调用方据此**保留**该行（不猜）。
fn line_addr(line: &str) -> Option<u64> {
    let t = line.trim_start().strip_prefix("0x")?;
    let i = t.find(':')?;
    let hex = &t[..i];
    if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}

/// 把反汇编注释块裁到 `limit` 之前。`lift` 是线性反汇编、地址单调递增，
/// 所以越界行一定连续出现在**末尾**：找到第一条就截断，不必逐行重建整串。
fn clip_raw(raw: &mut String, limit: u64) {
    let mut start = 0usize;
    while start < raw.len() {
        let end = match raw[start..].find('\n') {
            Some(i) => start + i + 1,
            None => raw.len(),
        };
        let over = match line_addr(&raw[start..end]) {
            Some(a) => a >= limit,
            None => false,
        };
        if over {
            raw.truncate(start);
            return;
        }
        if end >= raw.len() {
            return;
        }
        start = end;
    }
}

/// 寄存器角色（与 asm 导出同源；按平台 profile 取名）
#[derive(Clone)]
struct Roles {
    pp: String,
    thr: String,
    /// 对象池：偏移 → 可直接内联的 Dart 值。字符串字面量直接写出来（这是可读性
    /// 跳跃最大的一步：`x0 = mem(PP, 0x4178)` → `x0 = "objects"`），立即数写成数字，
    /// 别的对象写成类名注释。Stub 条目没有值可展示，不入表。
    pool: BTreeMap<u64, String>,
    /// Dart 代码里的栈指针寄存器名（arm64 是 x15 —— SDK constants_arm64.h 的
    /// `R15 = 15; // SP in Dart code.`；x64 是 rsp）
    sp: String,
    /// 平台 profile 的 register_aliases（寄存器名 → 框架名）
    aliases: std::collections::HashMap<String, String>,
    /// 平台 profile 的 non_field_base：不可能持有对象基址的寄存器（blutter 口径）
    non_field: BTreeSet<String>,
    /// **预解析**的寄存器别名表：token → 最终替换值。见 `mask_regs`。
    mask_map: std::collections::HashMap<String, String>,
}

impl Roles {
    /// 渲染后的寄存器名是否可能是对象基址。两边都要认：arm64 产物里写的是角色名
    /// （PP/THR/BARRIER…），x64 产物里是裸寄存器名（r14/rsp/rbx…），而
    /// non_field_base 记的是**裸名**。
    fn obj_base(&self, name: &str) -> bool {
        if self.non_field.contains(name) {
            return false;
        }
        let role = self
            .aliases
            .get(name)
            .map(|x| x.as_str())
            .unwrap_or(name)
            .to_ascii_uppercase();
        if self.non_field.contains(&role) {
            return false;
        }
        !matches!(
            role.as_str(),
            "PP" | "THR" | "SP" | "FP" | "HEAP" | "NULL" | "BARRIER" | "CODE_REG" | "LR"
                | "XZR" | "WZR" | "DISPATCH" | "TMP" | "IC_DATA"
        )
    }
}

fn roles(analyzer: &Analyzer) -> Roles {
    let r = &analyzer.platform.registers;
    let g = |k: &str, d: &str| r.get(k).cloned().unwrap_or_else(|| d.to_string());
    let aliases = analyzer.platform.register_aliases.clone();
    let pp = g("pp", "pp");
    let thr = g("thr", "thr");
    Roles {
        sp: g("sp", "sp"),
        non_field: analyzer.platform.non_field_base.iter().cloned().collect(),
        pool: pool_map(analyzer),
        mask_map: build_mask_map(&aliases, &pp, &thr),
        aliases,
        pp,
        thr,
    }
}

/// 对象池引用的查询门面（`dae findrefs` 用）。
///
/// 它不重新实现任何解析：值文本来自 `pool_map`（与 `text/pp.txt` 同源），
/// 操作数→池偏移来自 `mask_regs` + `mem_parts` + `pool_key`（与反编译产物里
/// `x0 = "Hello" /* pp+0x17f8 */` 那条注释同源）。所以 findrefs 报出的偏移
/// **就是**产物里注释的那个偏移，这条等价关系是可以断言的（见 tests/cli_query.rs），
/// 不需要相信实现。
pub struct PoolRefs {
    rl: Roles,
    /// 偏移 → 与 `text/pp.txt` **同形**的完整描述（`dae pp` 用的也是这个）。
    ///
    /// 之所以要单独存一份，而不是直接用 `rl.pool`：`pool_map` 的值是「可内联进 Dart 代码的
    /// 形式」，而 `dart_literal` 会在 **60 字符处截断**并加 `...`。拿截断形去检索会
    /// **静默漏掉**落在后半段的子串——实测语料里就有
    /// `"Error handler must accept one Object or one Object and a Sta..."`，
    /// 搜 `StackTrace as arguments` 一个都命中不了。对一个搜索命令来说这不可接受。
    /// 顺带也让 `findrefs` 的值列与 `dae pp` / `text/pp.txt` 一致，不再是两套文本。
    full: BTreeMap<u64, String>,
}

impl PoolRefs {
    pub fn new(analyzer: &Analyzer) -> Self {
        let mut full = BTreeMap::new();
        if let Some(entries) = analyzer.iso.objectpool_entries.as_ref() {
            for (i, ent) in entries.iter().enumerate() {
                let mut t = String::new();
                crate::export::ppobjs::pp_describe(analyzer, &mut t, ent);
                full.insert(crate::export::ppobjs::pp_offset(i), t);
            }
        }
        Self {
            rl: roles(analyzer),
            full,
        }
    }

    /// 池条目总数。
    pub fn len(&self) -> usize {
        self.rl.pool.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rl.pool.is_empty()
    }

    /// 含 `needle` 的条目：`(偏移, 完整描述, 是不是字符串字面量)`。
    ///
    /// 大小写不敏感子串，与 `dae strings -f` 同口径。**完整描述与内联形都要搜**：
    /// 前者可能带 `String: ` 这类前缀，后者可能截断，只搜一边都会漏。
    ///
    /// 第三个字段用来区分 kind，判据是内联形的形状而不是猜：`pool_map` 把字符串字面量
    /// 写成 `"…"`（带引号），把其它对象写成 `/* 类名 */` 注释。
    pub fn values_containing(&self, needle: &str) -> Vec<(u64, String, bool)> {
        let n = needle.to_lowercase();
        self.rl
            .pool
            .iter()
            .filter_map(|(k, inline)| {
                let full = self.full.get(k).cloned().unwrap_or_else(|| inline.clone());
                if !full.to_lowercase().contains(&n) && !inline.to_lowercase().contains(&n) {
                    return None;
                }
                Some((*k, full, inline.starts_with('"')))
            })
            .collect()
    }

    /// 某个偏移的值文本。
    pub fn value_at(&self, off: u64) -> Option<&str> {
        self.rl.pool.get(&off).map(|s| s.as_str())
    }

    /// 对象种类恰为 `name` 的条目：`(偏移, 完整描述)`。大小写不敏感、**整名精确**。
    ///
    /// 「种类」就是 `pool_map` 给非字符串条目生成的那个 `/* X */` 注释里的 X
    /// （实测语料里有 ImmutableArray / Type / Field / Function / TypeParameter /
    /// SubtypeTestCache / TypeArguments / Stub），也就是反编译产物里
    /// `x1 = mem((PP + 0x18000), 0x768) /* TypeArguments */` 那个词。
    ///
    /// ⚠️ 这**不是**类型名。`describe_into` 写的是 `Kind: 内容`，所以种类前缀是对象自身的
    /// 类别；拿它当「按类型名检索」会既漏又误（搜 `Field` 命中的是所有 Field 对象，
    /// 与具体哪个字段无关）。命令因此叫 `kind` 而不叫 `type`。
    pub fn entries_of_kind(&self, name: &str) -> Vec<(u64, String)> {
        let want = name.to_lowercase();
        self.rl
            .pool
            .iter()
            .filter_map(|(k, inline)| {
                let inner = inline
                    .strip_prefix("/* ")
                    .and_then(|s| s.strip_suffix(" */"))?
                    .trim();
                if !inner.eq_ignore_ascii_case(&want) {
                    return None;
                }
                Some((
                    *k,
                    self.full.get(k).cloned().unwrap_or_else(|| inline.clone()),
                ))
            })
            .collect()
    }

    /// 池里实际出现过的对象种类（按条数降序），用于没命中时给可操作提示。
    pub fn kinds(&self) -> Vec<(String, usize)> {
        let mut m: BTreeMap<&str, usize> = BTreeMap::new();
        for inline in self.rl.pool.values() {
            if let Some(inner) = inline
                .strip_prefix("/* ")
                .and_then(|s| s.strip_suffix(" */"))
                .map(|s| s.trim())
            {
                if !inner.is_empty() {
                    *m.entry(inner).or_insert(0) += 1;
                }
            }
        }
        let mut v: Vec<(String, usize)> = m.into_iter().map(|(k, n)| (k.to_string(), n)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    }

    /// 这条**原始 capstone 操作数文本**是否在读某个池槽；是则返回偏移。
    ///
    /// 先过 `mask_regs`（把 `x27`/`r15` 之类还原成角色名 `PP`）再解析，与反编译器
    /// 走同一条路。没有 `[` 的操作数不可能是内存引用，直接早退——扫全量指令时
    /// 绝大多数指令走这条，省掉一次 String 分配。
    pub fn offset_in_operand(&self, raw_ops: &str) -> Option<u64> {
        if !raw_ops.contains('[') {
            return None;
        }
        let masked = mask_regs(&self.rl, raw_ops);
        pool_key(&self.rl, &mem_parts(&masked))
    }
}

#[cfg(feature = "asm")]
pub fn pool_debug(analyzer: &Analyzer) -> usize {
    let m = pool_map(analyzer);
    eprintln!(
        "[dbg-pool] entries={:?} mapped={}",
        analyzer
            .iso
            .objectpool_entries
            .as_ref()
            .map(|v| v.len()),
        m.len()
    );
    if std::env::var("DART_AOT_DEBUG_DEC").is_ok() {
        for (k, v) in m.iter().take(6) {
            eprintln!("[dbg-pool]   {k:#x} = {v}");
        }
        for (k, v) in m.iter().filter(|(_, v)| v.starts_with('"')).take(3) {
            eprintln!("[dbg-pool]   str {k:#x} = {v}");
        }
        for (k, v) in m.iter().filter(|(_, v)| v.starts_with("/*")).take(6) {
            eprintln!("[dbg-pool]   cmt {k:#x} = {v}");
        }
    }
    m.len()
}

/// 对象池表：`0x10 + i*8` 是池内偏移（与 pp.txt 一致）。
/// 只收**能表达成 Dart 值**的条目；Stub / 解析不出的条目留空（宁可不写，不编）。
fn pool_map(analyzer: &Analyzer) -> BTreeMap<u64, String> {
    let mut m = BTreeMap::new();
    let Some(entries) = analyzer.iso.objectpool_entries.as_ref() else {
        return m;
    };
    for (i, ent) in entries.iter().enumerate() {
        let off = 0x10 + i as u64 * 8;
        match ent.typ {
            PoolKind::Imm => {
                let v = ent.value.unwrap_or(0);
                m.insert(off, v.to_string());
            }
            PoolKind::Obj => {
                let vref = ent.value.unwrap_or(0) as u64;
                // 先按**字符串对象**直接取值：`sref_str` 只认"这个 ref 是字符串"，
                // 不依赖 cid 编号表（`describe_into` 走的是 cid==93/94 的判断，
                // 老版本 profile 的 cid 枚举一偏，字符串就被描述成类名 `String`）。
                if let Some(text) = analyzer.sref_str(vref) {
                    if let Some(lit) = dart_literal(text) {
                        m.insert(off, lit);
                        continue;
                    }
                    // 长文本/非 ASCII（Unicode 数据表那类）：不内联，留类型注释
                    m.insert(off, "/* String */".to_string());
                    continue;
                }
                // 其它对象：类名注释（比裸 mem() 有信息量）
                let mut t = String::new();
                crate::export::ppobjs::describe_into(analyzer, &mut t, vref, 0);
                if let Some(name) = t.split(':').next() {
                    if !name.is_empty() && name.len() < 40 {
                        m.insert(off, format!("/* {name} */"));
                    }
                }
            }
            _ => {}
        }
    }
    m
}

/// 池里的字符串 → Dart 字面量。两条纪律：
/// 1. **只收纯 ASCII 可打印**：池里混着 Unicode 数据表之类的大块二进制（实测有整段
///    CJK/控制字符），内联出来既读不懂也会破坏"产物零非 ASCII"的仓库口径；
/// 2. **自己转义**：上游 `describe_into` 只做 `"{}"` 拼接，字符串里带引号/换行就会
///    把产物写成非法 Dart。
///
/// 不合规的（含非 ASCII、控制字符过多）返回 None → 调用方退回原来的 `mem(...)` 写法。
fn dart_literal(raw: &str) -> Option<String> {
    const MAX: usize = 60;
    let printable = raw
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .count();
    if raw.chars().any(|c| c as u32 > 0x7e) || printable * 5 < raw.chars().count() * 4 {
        return None;
    }
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('"');
    for (n, c) in raw.chars().enumerate() {
        if n >= MAX {
            out.push_str("...");
            break;
        }
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // `$` 必须转义：池里的字符串常带 Dart 的 `$` 前缀（实测真机应用里有
            // `"$IsolateException"`），不转义就是字符串插值 → dart analyze 报
            // undefined_identifier，产物不再是合法 Dart。
            '$' => out.push_str("\\$"),
            _ => out.push(c),
        }
    }
    out.push('"');
    Some(out)
}

/// 单条指令 → IR。**认不出就 Other**，不做语义猜测。
fn lift_one(rl: &Roles, is_arm64: bool, mnem: &str, ops: &str, addr: u64) -> Op {
    let reg_name = |r: &str| -> String {
        // 用框架名替代硬编码寄存器名，产物可读性更好
        match r {
            "sp" | "rsp" => "SP".to_string(),
            "fp" | "rbp" | "x29" => "FP".to_string(),
            "lr" | "x30" => "LR".to_string(),
            other => {
                if other == rl.pp {
                    "PP".into()
                } else if other == rl.thr {
                    "THR".into()
                } else {
                    other.to_string()
                }
            }
        }
    };
    let first = ops.split(',').next().unwrap_or("").trim().to_string();
    let rest = ops
        .split_once(',')
        .map(|(_, r)| r.trim().to_string())
        .unwrap_or_default();
    let is_reg = |s: &str| {
        !s.is_empty()
            && !s.contains(' ')
            && !s.contains('[')
            && !s.starts_with('#')
            && !s.chars().next().unwrap().is_ascii_digit()
    };

    // 返回
    if mnem == "ret" || (is_arm64 && mnem == "ret") {
        return Op::Return { value: None };
    }
    if !is_arm64 && mnem == "ret" {
        return Op::Return { value: None };
    }
    // 调用
    if mnem == "bl" || mnem == "call" || mnem == "callq" {
        let t = parse_addr(ops);
        return Op::Call {
            dst: None,
            target: t,
            callee: ops.trim().to_string(),
            resolved: None, // 由 lift 用函数名表回填
        };
    }
    if mnem == "blr" {
        return Op::Call {
            dst: None,
            target: None,
            callee: reg_name(ops.trim()),
            resolved: None,
        };
    }
    // 条件/无条件跳转
    if mnem == "b" || mnem == "jmp" {
        if let Some(t) = parse_addr(ops) {
            return Op::Branch { cond: None, target: t };
        }
        return Op::Branch {
            cond: None,
            target: 0,
        };
    }
    if mnem.starts_with("b.") || (mnem.starts_with('j') && mnem != "jmp") {
        let t = parse_addr(ops).unwrap_or(0);
        // 条件来源：arm64 看上一条 cmp；x86 看标志位——这里只如实记 mnemonic
        return Op::Branch {
            cond: Some(mnem.to_string()),
            target: t,
        };
    }
    // 池加载：ldr rN, [PP, #off] / mov rN, [PP+off]（x86）
    //
    // ⚠️ 必须**按词边界**匹配，不能 `ops.contains(rl.pp)`。Dart arm64 的池指针 PP
    // 物理寄存器名是 `x27`，而位移文本 `#0x27` 里**正好含有子串 `x27`** ⇒
    // `stur x17, [x3, #0x27]` 会被误判成池加载，返回 `Expr::Pool(0x27)`：
    // ① **store 被当成赋值**，方向反转，`memSet(x3, 0x27, x17)` 这个写**彻底消失**；
    // ② `Expr::Pool` 渲染成 `pp[0x27]`，再经出口的 `sanitize_mem_refs` 把 `[..]`
    //    改写成 `mem(..)`，于是产物里出现凭空捏造的 **`ppmem(0x27)`**；
    // ③ load 侧同样丢基址：`ldur x1,[x0,#0x27]` 与二级解引用 `ldur x2,[x1,#0x27]`
    //    渲染成同一个 `ppmem(0x27)`，双重间接被别名成同一个值。
    // 实测 Reqable：`ppmem(` **1411 处**，全部 16 种偏移都以 `0x27` 开头、
    // 而 `mem(..., 0x27*)` **零幸存**（`mem(PP,0x5270)`/0x26x/0x28x 全正常）——
    // 这个「纯前缀相关」的分布就是子串误匹配的指纹。
    let ppx = rl.pp.to_uppercase();
    if (contains_word(ops, &ppx) || contains_word(ops, &rl.pp))
        && is_reg(&first) {
            let idx = ops
                .rfind("#0x")
                .and_then(|i| u64::from_str_radix(&ops[i + 3..], 16).ok())
                .or_else(|| ops.rfind("0x").and_then(|i| {
                    let h: String = ops[i + 2..].chars().take_while(|c| c.is_ascii_hexdigit()).collect();
                    u64::from_str_radix(&h, 16).ok()
                }))
                .unwrap_or(0);
            return Op::Assign {
                dst: reg_name(&first),
                src: Expr::Pool(idx),
            };
        }
    // 寄存器间 move
    if mnem == "mov" || mnem == "movq" || mnem == "movabs" {
        if is_reg(&first) && is_reg(&rest) {
            return Op::Assign {
                dst: reg_name(&first),
                src: Expr::Reg(reg_name(&rest)),
            };
        }
        if is_reg(&first) {
            if let Some(v) = parse_imm_i(&rest) {
                return Op::Assign {
                    dst: reg_name(&first),
                    src: Expr::Imm(v),
                };
            }
            return Op::Assign {
                dst: reg_name(&first),
                src: Expr::Mem(rest.clone()),
            };
        }
    }
    // 加载：ldr/ldur 等 → 目标寄存器 + 内存表达式原文。
    // **排除 ldp/ldpsw**：成对加载是「两寄存器 + 一个地址」，落到这里会把第二个
    // 寄存器当地址渲染成 `FP = mem(LR, [SP], #0x10)`（实测真实 app 的收尾指令）。
    if is_reg(&first)
        && !mnem.starts_with("ldp")
        && (mnem.starts_with("ldr") || mnem.starts_with("ldur") || mnem.starts_with("ld"))
        && is_arm64
    {
        return Op::Assign {
            dst: reg_name(&first),
            src: Expr::Mem(rest.clone()),
        };
    }
    // ---- 比较：喂给紧随的条件跳转（arm64 是 cmp/cmn/tst；x64 是 cmp/test）----
    if matches!(mnem, "cmp" | "cmn" | "tst" | "test") {
        return Op::Other(format!("{mnem} {ops}").trim().to_string());
    }
    // ---- 条件跳转：零比较与位测试自带条件，不必依赖上一条 ----
    if mnem == "cbz" || mnem == "cbnz" {
        let (a, target) = (first.clone(), ops.split_once(',').map(|x| x.1).unwrap_or(""));
        let op = if mnem == "cbz" { "==" } else { "!=" };
        return Op::Branch {
            cond: Some(format!("{} {op} 0", a)),
            target: parse_addr(target).unwrap_or(0),
        };
    }
    if mnem == "tbz" || mnem == "tbnz" {
        let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
        if parts.len() >= 3 {
            let op = if mnem == "tbz" { "==" } else { "!=" };
            // 被测寄存器是 32 位视图 `wN` 时，改用同一个物理寄存器的 64 位名 `xN`。
            //
            // 这是**可证明精确**的，不是近似：`tbz/tbnz` 的位号对 w 形式必然 ≤ 31，
            // 而对 k < 32，`wN` 的第 k 位与 `xN` 的第 k 位恒等（`wN` 就是 `xN` 的低 32 位），
            // 与高位是什么、之前谁写过它都无关 ⇒ 不需要补 `& 0xffffffff` 掩码。
            //
            // 为什么必须改：产物里 `wN` 与 `xN` 是两个独立的 Dart 变量，而编译器**极少**
            // 显式写 w 形式——`blr LR; tbz w0, #4` 里的 w0 是调用返回的 x0 的低半部，
            // 全函数只写过 `x0`，于是 `w0` 从未被赋值，条件在对 `null` 求值。
            // 实测 Reqable：这类「写 xN 后读 wN」的陈旧读 **1690 处**（w0 占 1291）。
            // 这是上一轮修的「写 wN 后读 xN」的**镜像方向**；那个方向靠补别名赋值解决，
            // 这个方向不需要——换成同一个名字就对了。
            let reg = {
                let r = parts[0];
                match r.strip_prefix('w') {
                    Some(n) if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) => {
                        format!("x{n}")
                    }
                    _ => r.to_string(),
                }
            };
            // ⚠️ 这里**刻意不做**「测第 0 位 ⇒ isSmi/isHeapObject」的语义还原。
            //
            // 试过，并且是错的：位号相同不代表语义相同。`tagging.heap_object_tag` 确实
            // 说明「tagged 指针的第 0 位区分 Smi 与 HeapObject」，但 `tbz/tbnz xN, #0`
            // 也用于**未装箱整数的奇偶测试**——源码 `n.isEven ? 'even' : 'odd'`
            // 编译出来就是 `tbnz w1, #0`，w1 里是个 int，根本不是指针。
            // 把它渲染成 `isHeapObject(w1)` 是**编造语义**（testing/stress 样例实测命中：
            // 产物变成 `if (isHeapObject(w1)) { "odd" } else { "even" }`），
            // 比原来的 `w1 & (1 << 0) != 0` 更糟——后者朴素但**正确**。
            //
            // 要安全地做这个还原，必须先证明「该寄存器此刻持有 tagged 值」，那需要类型或
            // 数据流信息（产物里全是 `dynamic`，没有）。所以保持位运算原样：
            // 它是机器真正做的事，读者可以自己判断这是标记测试还是奇偶测试。
            return Op::Branch {
                cond: Some(format!("{reg} & (1 << {}) {op} 0", parts[1])),
                target: parse_addr(parts[2]).unwrap_or(0),
            };
        }
    }
    // ---- 算术/逻辑：渲染成二元表达式（可读性主要来自这里）----
    let binop = match mnem {
        "add" | "adds" => Some("+"),
        "sub" | "subs" => Some("-"),
        "and" | "ands" => Some("&"),
        "orr" | "or" => Some("|"),
        "eor" | "xor" => Some("^"),
        "lsl" | "shl" => Some("<<"),
        "lsr" | "shr" => Some(">>"),
        "asr" | "sar" => Some(">>"),
        "mul" | "imul" => Some("*"),
        "sdiv" | "udiv" => Some("/"),
        _ => None,
    };
    if let Some(op) = binop {
        // 顶层逗号切分：`add x8, PP, #0xa, lsl #12` 的第 4 段是**移位修饰**，
        // 用 split(',') 会把它连同 shift 一起丢掉——`(PP + #0xa)` 少了 <<12，
        // 池地址全错。这里把修饰折进操作数。
        let parts: Vec<&str> = split_operands(ops).iter().map(|s| s.trim()).collect();
        if parts.len() >= 3 && is_reg(parts[0]) {
            // 三操作数：dst = a op b。**不能**用"第二操作数是不是寄存器"来判定——
            // x86 的 `imul ecx, [rax], 0x48` 第二操作数是内存，旧写法会把第三段
            // 当成移位修饰，渲染出 `ecx * (mem(rax) 0x48)`（语法错误）。
            let rhs = shift_operand(parts[2], parts.get(3).copied())
                .unwrap_or_else(|| parts[2].to_string());
            return Op::Assign {
                dst: reg_name(parts[0]),
                src: Expr::Text(format!("{} {op} {rhs}", parts[1])),
            };
        }
        if parts.len() == 2 && is_reg(parts[0]) {
            // 两操作数：`add x0, x1` / `add rax, [rbx]` 都是 dst op= src
            let rhs = shift_operand(parts[1], None).unwrap_or_else(|| parts[1].to_string());
            return Op::Assign {
                dst: reg_name(parts[0]),
                src: Expr::Text(format!("{} {op} {rhs}", reg_name(parts[0]))),
            };
        }
    }
    // ---- 位域提取 ubfx dst, src, lsb, width → (src >> lsb) & ((1<<width)-1) ----
    if mnem == "ubfx" || mnem == "sbfx" {
        let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
        if parts.len() == 4 && is_reg(parts[0]) {
            if let (Some(lsb), Some(w)) = (parse_imm_i(parts[2]), parse_imm_i(parts[3])) {
                let mask = (1i64 << w) - 1;
                return Op::Assign {
                    dst: reg_name(parts[0]),
                    src: Expr::Text(format!("({} >> {lsb}) & {mask:#x}", parts[1])),
                };
            }
        }
    }
    // ---- adcs/sbcs：带进位/借位的加减（多精度算术的中间步）----
    // 进位标志是**跨指令的隐式状态**，产物里没有建模，所以不能写成 `a + b`（那是错的，
    // 会丢掉进位）。前导里已经声明了 `addCarry`/`subBorrow` 两个占位函数，接上去即可：
    // 如实说明「这里是一次带进位的加法」，而不猜进位的值。
    // 这是 material_3_demo 上最后 2 条 unmapped（`adcs`），补完全量产物 unmapped 归零。
    if is_arm64 && matches!(mnem, "adc" | "adcs" | "sbc" | "sbcs") {
        let parts: Vec<&str> = split_operands(ops).iter().map(|s| s.trim()).collect();
        if parts.len() >= 3 && is_reg(parts[0]) {
            return Op::Assign {
                dst: reg_name(parts[0]),
                src: Expr::Text(format!(
                    "{}({}, {}) /* carry flag not modelled */",
                    if mnem == "adc" || mnem == "adcs" {
                        "addCarry"
                    } else {
                        "subBorrow"
                    },
                    parts[1],
                    parts[2]
                )),
            };
        }
    }
    // ---- x86 inc/dec dst → dst ± 1（不影响 CF，这里只表达算术效果）----
    if !is_arm64 && (mnem == "inc" || mnem == "dec") {
        let d = ops.trim();
        if is_reg(d) {
            return Op::Assign {
                dst: reg_name(d),
                src: Expr::Text(format!(
                    "{} {} 1",
                    reg_name(d),
                    if mnem == "inc" { "+" } else { "-" }
                )),
            };
        }
    }
    // ---- x86 cdq/cqo：把 eax/rax 的符号位铺满 edx/rdx（idiv 之前的高半部）----
    if !is_arm64 && (mnem == "cdq" || mnem == "cqo") {
        let (hi, lo, bits) = if mnem == "cdq" {
            ("edx", "eax", 31)
        } else {
            ("rdx", "rax", 63)
        };
        return Op::Assign {
            dst: hi.to_string(),
            src: Expr::Text(format!(
                "(({lo} >> {bits}) & 1) == 0 ? 0 : -1 /* {mnem}: sign-extend for idiv */"
            )),
        };
    }
    // ---- x86 cmov<cc> dst, src → dst = cond ? src : dst（与 arm64 csel 同族）----
    if let Some(cc) = is_x86_cmov(mnem) {
        let parts: Vec<&str> = split_operands(ops).iter().map(|s| s.trim()).collect();
        if parts.len() == 2 && is_reg(parts[0]) {
            // 条件码包成 condFlag(...)，交给 lift() 的折叠臂用上一条 cmp 折成真条件
            return Op::Assign {
                dst: reg_name(parts[0]),
                src: Expr::Text(format!(
                    "({}) ? {} : {}",
                    sel_cond(cc),
                    parts[1],
                    reg_name(parts[0])
                )),
            };
        }
    }
    // ---- arm64 cinc/cinv/cneg：csinc/csinv/csneg 的别名形式 ----
    // cinc xd, xn, cond  → xd = cond ? xn+1 : xn
    // cinv xd, xn, cond  → xd = cond ? ~xn   : xn
    // cneg xd, xn, cond  → xd = cond ? -xn   : xn
    if is_arm64 && (mnem == "cinc" || mnem == "cinv" || mnem == "cneg") {
        let parts: Vec<&str> = split_operands(ops).iter().map(|s| s.trim()).collect();
        if parts.len() == 3 && is_reg(parts[0]) {
            let on = match mnem {
                "cinc" => format!("{} + 1", parts[1]),
                "cinv" => format!("~{}", parts[1]),
                _ => format!("-{}", parts[1]),
            };
            return Op::Assign {
                dst: reg_name(parts[0]),
                src: Expr::Text(format!("({}) ? {on} : {}", sel_cond(parts[2]), parts[1])),
            };
        }
    }
    // ---- 条件选择 csel dst, a, b, cond → cond ? a : b ----
    if mnem == "csel" || mnem == "csinc" {
        let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
        if parts.len() == 4 && is_reg(parts[0]) {
            // 条件码（`hi`/`eq`…）不是 Dart 表达式：能从上一条 cmp 折出来就折，
            // 折不出来写成 `condFlag("hi")`——返回 bool 的占位函数，别硬塞裸标识符
            // （裸标识符会让 `(hi) ? a : b` 报 "Conditions must have a static type of 'bool'"）。
            let cond = sel_cond(parts[3]);
            return Op::Assign {
                dst: reg_name(parts[0]),
                src: Expr::Text(format!("({cond}) ? {} : {}", parts[1], parts[2])),
            };
        }
    }
    // ---- movk dst, #imm, lsl #16 → 拼接高位 ----
    if mnem == "movk" {
        let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
        if parts.len() >= 2 && is_reg(parts[0]) {
            if let Some(v) = parse_imm_i(parts[1]) {
                return Op::Assign {
                    dst: reg_name(parts[0]),
                    src: Expr::Text(format!("({} & 0xffff) | {:#x}", reg_name(parts[0]), v << 16)),
                };
            }
        }
    }
    // ---- 浮点：与整数同一套二元渲染 ----
    // arm64 是三操作数 `fadd d0, d1, d2`；x86 SSE 是**两操作数** `addsd xmm0, xmm1`
    // （= `xmm0 = xmm0 + xmm1`）。两种形态都要认——x86 的标量浮点算术全走 `*sd`/`*ss`，
    // 漏掉它们等于把所有 double/float 运算丢成 `// unmapped`。
    // 实测 hello_3.13.0（x64）未映射 161 行里 mulsd 4 + addsd 2 + subps 1；
    // T4_blank 34 行里 comisd 5 + mulsd 4 + addsd 2。
    let fbin = match mnem {
        "fadd" | "addsd" | "addss" => Some("+"),
        "fsub" | "subsd" | "subss" => Some("-"),
        "fmul" | "mulsd" | "mulss" => Some("*"),
        "fdiv" | "divsd" | "divss" => Some("/"),
        _ => None,
    };
    if let Some(op) = fbin {
        let parts: Vec<&str> = split_operands(ops).iter().map(|s| s.trim()).collect();
        // x86 两操作数形态
        if parts.len() == 2 && is_reg(parts[0]) && is_reg(parts[1]) && !is_arm64 {
            return Op::Assign {
                dst: reg_name(parts[0]),
                src: Expr::Text(format!(
                    "({} {op} {}) /* float */",
                    reg_name(parts[0]),
                    reg_name(parts[1])
                )),
            };
        }
        if parts.len() >= 3 && is_reg(parts[0]) {
            return Op::Assign {
                dst: reg_name(parts[0]),
                src: Expr::Text(format!("({} {op} {}) /* float */", parts[1], parts[2])),
            };
        }
    }
    // ---- 浮点一元/最值/转换：只标注读法，不猜类型 ----
    {
        let parts: Vec<&str> = split_operands(ops).iter().map(|s| s.trim()).collect();
        let d = parts.first().copied().unwrap_or("");
        let unary = match mnem {
            "fneg" => Some("-"),
            "fabs" => Some("abs"),
            "fsqrt" => Some("sqrt"),
            "fcvt" => Some("toDouble"),
            "fcvtn" => Some("toFloat"),
            "scvtf" => Some("toFloat"),
            "ucvtf" => Some("toFloatUnsigned"),
            "fcvtzs" => Some("toInt"),
            "fcvtzu" => Some("toIntUnsigned"),
            "scvtfw" | "scvtfx" => Some("toFloat"),
            _ => None,
        };
        if let Some(k) = unary {
            if is_reg(d) && parts.len() >= 2 && is_reg(parts[1]) {
                let src = match mnem {
                    "fneg" => format!("-{}", parts[1]),
                    "fabs" => format!("({}).abs()", parts[1]),
                    "fsqrt" => format!("({}).sqrt()", parts[1]),
                    "scvtf" | "ucvtf" | "fcvtzs" | "fcvtzu" | "fcvt" | "fcvtn" => {
                        format!("{k}({})", parts[1])
                    }
                    _ => format!("{k}({})", parts[1]),
                };
                return Op::Assign {
                    dst: reg_name(d),
                    src: Expr::Text(src),
                };
            }
        }
        // fmax/fmin：三操作数时第三段是条件，忽略（不猜），只表达最值
        if (mnem == "fmax" || mnem == "fmaxnm" || mnem == "fmin" || mnem == "fminnm")
            && parts.len() >= 3
            && is_reg(d)
        {
            let f = if mnem.starts_with("fmax") { "max" } else { "min" };
            return Op::Assign {
                dst: reg_name(d),
                src: Expr::Text(format!("{f}({}, {})", parts[1], parts[2])),
            };
        }
        // fmov 在两个寄存器之间搬运：整数/浮点寄存器互转（位模式不变），
        // 也用于常量池加载 `fmov d0, #1.0` —— 后者操作数是立即数，不伪造数值
        if mnem == "fmov" && parts.len() >= 2 && is_reg(d) {
            return Op::Assign {
                dst: reg_name(d),
                src: Expr::Text(format!("{} /* bits */", parts[1])),
            };
        }
        // 符号/零扩展与位段插入
        if (mnem == "sxtw" || mnem == "sxtb" || mnem == "sxth" || mnem == "uxtw"
            || mnem == "uxtb" || mnem == "uxth")
            && parts.len() >= 2
            && is_reg(d)
            && is_reg(parts[1])
        {
            return Op::Assign {
                dst: reg_name(d),
                // 扩展/位宽指令（`sxtw w1, w2`）写成声明过的占位函数：`(w2 as sxtw)` 是
            // 「把没赋值的 w 寄存器转型」→ dart analyze 报 cast_from_nullable_always_fails
            src: Expr::Text(format!("{mnem}({})", parts[1])),
            };
        }
        if (mnem == "ubfiz" || mnem == "sbfiz") && parts.len() >= 4 && is_reg(d) {
            let lsb = parse_imm_i(parts[2]).unwrap_or(0);
            let w = parse_imm_i(parts[3]).unwrap_or(0);
            let mask = if w >= 64 { u64::MAX } else { (1u64 << w) - 1 };
            return Op::Assign {
                dst: reg_name(d),
                src: Expr::Text(match mnem {
                    "sbfiz" => format!("(({} & {mask:#x}) << {lsb}) /* signed */", parts[1]),
                    _ => format!("(({} & {mask:#x}) << {lsb})", parts[1]),
                }),
            };
        }
        // cset dst, cond：条件成立取 1（csetm 成立取全 1）
        //
        // ⚠️ 条件码必须走 `sel_cond` 包成 `condFlag("ne")`，不能直接用 `parts[1]`：
        // 裸条件码不是 Dart 标识符，`(ne) ? 1 : 0` 会报 undefined_identifier。
        // 包起来之后 `lift()` 的折叠臂才能用 `sel_cc` 把它取回、再用上一条 `cmp`
        // 折成真条件（`csel`/`csinc` 一直是这么做的，cset 之前漏了）。
        if (mnem == "cset" || mnem == "csetm") && parts.len() >= 2 && is_reg(d) {
            return Op::Assign {
                dst: reg_name(d),
                src: Expr::Text(format!(
                    "({}) ? {} : 0",
                    sel_cond(parts[1]),
                    if mnem == "csetm" { "-1" } else { "1" }
                )),
            };
        }
        // x86 setcc dst8：条件成立取 1（arm64 `cset` 的对应物）。
        // 条件码只认 `fold_cond` 真能处理的白名单，认不出来就**不接管**——
        // 让它落到 `Op::Other` 的 `// unmapped: setne dl` 注释里（诚实、且计入
        // unmapped 指标），绝不编一个 `condFlag("j…")` 出来。
        if !is_arm64 {
            if let Some(cc) = is_x86_setcc(mnem) {
                if !parts.is_empty() && is_reg(d) {
                    return Op::Assign {
                        dst: reg_name(d),
                        src: Expr::Text(format!("({}) ? 1 : 0", sel_cond(cc))),
                    };
                }
            }
        }
        // adr：把它当「取本地址」——x64/arm64 都用于取常量标签
        if (mnem == "adr" || mnem == "adrp" || mnem == "lea") && is_reg(d) {
            // 操作数拆不出地址就别硬造 `addr()`（占位函数要 1 个参数）
            if parts.len() < 2 || parts[1].trim().is_empty() {
                return Op::Other(format!("{mnem} {ops}"));
            }
            let arg = parts[1].trim().trim_start_matches('#').to_string();
            return Op::Assign {
                dst: reg_name(d),
                src: Expr::Text(format!("addr({arg})")),
            };
        }
    }
    if mnem == "brk" {
        // Dart AOT 的 `brk #n` = 不可达/断言失败路径；它是**终止符**（不落入下一条），
        // 把它当普通语句会造出一条假的落空边（结构化器因此误判汇合点）。
        return Op::Abort(parse_imm_i(ops).unwrap_or(0));
    }
    // ---- 成对读写 stp/ldp：**栈基址**才是帧保存/恢复（纯簿记，合成注释）；
    //      其它基址是真实的对象字段读写，照常出语句。----
    if mnem == "stp" || mnem == "ldp" {
        let base = mem_base(ops);
        let is_stack = matches!(base, Some(b) if b == rl.sp.as_str() || b == "SP" || b == "sp");
        if is_stack {
            return Op::Note(format!("frame: {ops}"));
        }
        // 3 段 = 两个寄存器 + 一个地址（`ldp x0, x1, [x19, #0x10]`）
        let parts: Vec<&str> = split_operands(ops);
        let (regs, mem) = if parts.len() >= 3 {
            (
                format!("{}, {}", reg_name(parts[0].trim()), reg_name(parts[1].trim())),
                parts[2].trim().to_string(),
            )
        } else if parts.len() == 2 {
            // 少见的两段形式：目标寄存器列表已经在方括号里（`ldp x0, [x1], #16` 的后变址）
            (
                reg_name(parts[0].trim()),
                parts[1].trim().to_string(),
            )
        } else {
            return Op::Other(format!("{mnem} {ops}"));
        };
        if mnem.starts_with("stp") {
            return Op::Store {
                target: mem,
                value: regs,
            };
        }
        // ldp：拆成 memRead2(base, disp, d1, d2)
        let mp = mem_parts(&mem);
        let (base, disp) = (
            mp.parts.first().cloned().unwrap_or_default(),
            mp.parts.get(1).cloned().unwrap_or_else(|| "0".into()),
        );
        let (d1, d2) = match (parts.first(), parts.get(1)) {
            (Some(a), Some(b)) => (
                reg_name(a.trim()).to_string(),
                reg_name(b.trim()).to_string(),
            ),
            _ => return Op::Other(format!("{mnem} {ops}")),
        };
        return Op::PairLoad {
            base: base.trim_start_matches('#').to_string(),
            disp: disp.trim_start_matches('#').to_string(),
            d1,
            d2,
        };
    }
    // ---- arm64 间接跳转 `br x17`：跳转表分发，是终止符（不落入下一条）----
    if mnem == "br" || mnem == "braa" || mnem == "brab" {
        return Op::IndirectJump(reg_name(&first));
    }
    // ---- 交换：xchg a, b（x64 常见于自旋锁/交换）----
    // ---- 单操作数 imul（x86：RDX:RAX = RAX * 操作数）----
    if mnem.starts_with("imul") && !ops.contains(',') {
        return Op::Helper(format!("mul({first})"));
    }
    // ---- x86 带进位/借位的加减（隐含标志位）：占位调用，别假装是普通加减 ----
    //
    // 必须渲染成**赋值**，不是裸调用。x86 的 `adc rax, rbx` 语义是
    // `rax = rax + rbx + CF`，原来写成 `Op::Helper("addCarry(rax, rbx)")` 渲染成
    // `addCarry(rax, rbx);`——**对 rax 的写彻底消失**，后续读 rax 拿到旧值。
    // 这与本文件里修过的几处是同一类缺陷（结果没有落点）。
    //
    // ⚠️ 只有 x86 走这里：arm64 的 `adcs`/`sbcs` 是**三操作数**（`adcs xd, xn, xm`），
    // 由上面专门的分支处理。原来 `sbcs` 也列在这条 x86 两操作数路径里，于是 arm64 的
    // `sbcs x0, x1, x2` 被渲染成 `subBorrow(x0, x1)`——**第三个操作数被丢掉**，
    // 而且 x0 既当目标又当操作数，语义全错。
    if !is_arm64 && (mnem == "adc" || mnem == "adcx") {
        let parts: Vec<&str> = split_operands(ops).iter().map(|s| s.trim()).collect();
        if parts.len() >= 2 && is_reg(parts[0]) {
            return Op::Assign {
                dst: reg_name(parts[0]),
                src: Expr::Text(format!(
                    "addCarry({}, {}) /* carry flag not modelled */",
                    reg_name(parts[0]),
                    parts[1]
                )),
            };
        }
    }
    if !is_arm64 && (mnem == "sbb" || mnem == "sbc") {
        let parts: Vec<&str> = split_operands(ops).iter().map(|s| s.trim()).collect();
        if parts.len() >= 2 && is_reg(parts[0]) {
            return Op::Assign {
                dst: reg_name(parts[0]),
                src: Expr::Text(format!(
                    "subBorrow({}, {}) /* borrow flag not modelled */",
                    reg_name(parts[0]),
                    parts[1]
                )),
            };
        }
    }
    // ---- 浮点取整到整数（arm64 fcvtm* = floor, fcvtp* = ceil）----
    if mnem.starts_with("fcvtm") || mnem.starts_with("fcvtp") || mnem.starts_with("fcvta") {
        let parts: Vec<&str> = split_operands(ops).iter().map(|s| s.trim()).collect();
        if parts.len() >= 2 && is_reg(parts[0]) {
            let which = if mnem.starts_with("fcvtm") {
                "toIntFloor"
            } else if mnem.starts_with("fcvtp") {
                "toIntCeil"
            } else {
                "toIntRound"
            };
            return Op::Assign {
                dst: reg_name(parts[0]),
                src: Expr::Text(format!("{which}({})", parts[1])),
            };
        }
    }
    // ---- 融合乘减 msub d, n, m, a → d = a - (n * m) ----
    if mnem == "msub" {
        let parts: Vec<&str> = split_operands(ops).iter().map(|s| s.trim()).collect();
        if parts.len() >= 4 && is_reg(parts[0]) {
            return Op::Assign {
                dst: reg_name(parts[0]),
                src: Expr::Text(format!("{} - ({} * {})", parts[3], parts[1], parts[2])),
            };
        }
    }
    // ---- 向量逻辑运算（xorps/andpd …）：与整数同形，标注 vector ----
    if matches!(mnem, "xorps" | "xorpd" | "andps" | "andpd" | "orps" | "orpd") {
        let parts: Vec<&str> = split_operands(ops).iter().map(|s| s.trim()).collect();
        if parts.len() >= 2 && is_reg(parts[0]) {
            let op = if mnem.starts_with("xor") {
                "^"
            } else if mnem.starts_with("and") {
                "&"
            } else {
                "|"
            };
            let rhs = if parts.len() >= 3 { parts[2] } else { parts[1] };
            return Op::Assign {
                dst: reg_name(parts[0]),
                src: Expr::Text(format!("({} {op} {rhs}) /* vector */", parts[1])),
            };
        }
    }
    // ---- 释放语义的存储（arm64 stlr）：就是一次存储 ----
    if mnem.starts_with("stlr") {
        return Op::Store {
            target: rest.clone(),
            value: reg_name(&first),
        };
    }
    if mnem.starts_with("xchg") {
        let parts: Vec<&str> = split_operands(ops).iter().map(|s| s.trim()).collect();
        if parts.len() >= 2 {
            return Op::Helper(format!("xchg({}, {})", parts[0], parts[1]));
        }
    }
    // ---- 单操作数 neg（x64 `neg rax`）：dst = -dst ----
    if mnem == "neg" && is_reg(&first) && rest.is_empty() {
        return Op::Assign {
            dst: reg_name(&first),
            src: Expr::Text(format!("-{}", reg_name(&first))),
        };
    }
    // ---- 有符号除法（x86 idiv 用隐含的 RDX:RAX，操作数里看不出来）：写成占位调用 ----
    if mnem.starts_with("idiv") {
        return Op::Helper(format!("idiv({first})"));
    }
    // ---- 高位乘法（umulh/smulh）：结果取自乘积高位 ----
    if mnem == "umulh" || mnem == "smulh" {
        let parts: Vec<&str> = split_operands(ops).iter().map(|s| s.trim()).collect();
        if parts.len() >= 3 {
            return Op::Assign {
                dst: reg_name(parts[0]),
                src: Expr::Text(format!("mulHigh({} * {})", parts[1], parts[2])),
            };
        }
    }
    // ---- 前导零计数 ----
    if mnem == "clz" && is_reg(&first) && !rest.is_empty() {
        return Op::Assign {
            dst: reg_name(&first),
            src: Expr::Text(format!("clz({rest})")),
        };
    }
    // ---- 独占存储（atomics）：目标寄存器是状态码，语义用占位调用表达 ----
    if mnem == "stxr" || mnem == "stlxr" {
        let parts: Vec<&str> = split_operands(ops).iter().map(|s| s.trim()).collect();
        if parts.len() >= 3 {
            return Op::Helper(format!("stxr({}, {})", reg_name(parts[0]), parts[2]));
        }
    }
    if mnem == "clrex" {
        return Op::Note("clrex (clear exclusive)".to_string());
    }
    // ---- 浮点搬移/转换（x64 SSE）：movsd/movss/movd 等搬移，cvt* 转换 ----
    if (mnem.starts_with("movs") || mnem.starts_with("movd") || mnem.starts_with("movq")
        || mnem.starts_with("movl"))
        && !first.is_empty()
    {
        if first.contains('[') {
            return Op::Store {
                target: first.clone(),
                value: rest.trim().to_string(),
            };
        }
        if !rest.is_empty() {
            return Op::Assign {
                dst: reg_name(&first),
                src: Expr::Reg(reg_name(&rest)),
            };
        }
    }
    if mnem.starts_with("cvt") {
        let parts: Vec<&str> = split_operands(ops).iter().map(|s| s.trim()).collect();
        if parts.len() >= 2 && is_reg(parts[0]) {
            // 只标读法，不猜位宽
            let conv = if mnem.contains("2sd") {
                "toDouble"
            } else if mnem.contains("2ss") {
                "toFloat"
            } else if mnem.contains("2si") || mnem.contains("2sq") {
                "toInt"
            } else {
                "convert"
            };
            return Op::Assign {
                dst: reg_name(parts[0]),
                src: Expr::Text(format!("{conv}({})", parts[1])),
            };
        }
    }
    // ---- x64 帧簿记：push/pop（含 push rbp 的序言、pop rbp 的收尾）与对齐填充 ----
    if matches!(mnem, "push" | "pop" | "int3" | "nop" | "endbr64" | "endbr32") {
        return Op::Note(format!("frame/align: {mnem} {ops}").trim().to_string());
    }
    // ---- 屏障 ----
    if mnem == "dmb" || mnem == "dsb" || mnem == "isb" {
        return Op::Note(format!("barrier: {mnem} {ops}"));
    }
    // ---- 栈帧指针搬运：mov FP, SP / add FP, SP, #n 之外的 sp 调整 ----
    if mnem == "sub" && ops.trim_start().starts_with("SP,") {
        return Op::Note(format!("frame: {ops}"));
    }
    if mnem == "add" && ops.trim_start().starts_with("SP,") {
        return Op::Note(format!("frame: {ops}"));
    }
    // ---- 负号/取反 ----
    if (mnem == "neg" || mnem == "mvn")
        && is_reg(&first) && is_reg(&rest) {
            return Op::Assign {
                dst: reg_name(&first),
                src: Expr::Text(format!("-{}", reg_name(&rest))),
            };
        }
    // ---- x64 零/符号扩展：movzx dst, byte ptr [..] 等 ----
    if mnem.starts_with("movzx") || mnem.starts_with("movsx") {
        let signed = mnem.starts_with("movsx");
        let width = if ops.contains("byte") {
            "u8"
        } else if ops.contains("word") {
            "u16"
        } else {
            "u32"
        };
        let w = if signed { width.replace('u', "i") } else { width.to_string() };
        return Op::Assign {
            dst: reg_name(&first),
            src: Expr::Text(format!("({} as {w})", rest)),
        };
    }
    // ---- movups/movdqu：与 mov 同形（向量寄存器搬运）----
    if mnem.starts_with("movup") || mnem.starts_with("movdq") || mnem.starts_with("movap") {
        if first.contains('[') {
            return Op::Store {
                target: first.clone(),
                value: rest.trim().to_string(),
            };
        }
        return Op::Assign {
            dst: reg_name(&first),
            src: Expr::Reg(reg_name(&rest)),
        };
    }
    // ---- 写内存：arm64 str*/stur*，x64 mov [..], reg ----
    if (mnem.starts_with("str") || mnem.starts_with("stur")) && is_arm64 {
        return Op::Store {
            target: rest.clone(),
            value: reg_name(&first),
        };
    }
    if mnem.starts_with("mov") && !is_arm64 && first.contains('[') {
        let v = rest.trim().to_string();
        return Op::Store {
            target: first.clone(),
            value: v,
        };
    }
    let _ = addr;
    Op::Other(format!("{mnem} {ops}").trim().to_string())
}


/// 把 arm64 的移位/扩展修饰折进操作数。
/// `#0xa` + `lsl #12` → `0xa000`（两个都是立即数时直接算出来）；
/// `x1` + `lsl #2` → `(x1 << 2)`；认不出的修饰原样保留成一个括注（不猜语义）。
fn shift_operand(operand: &str, modifier: Option<&str>) -> Option<String> {
    let Some(m) = modifier else {
        return Some(operand.to_string());
    };
    let m = m.trim();
    if m.is_empty() {
        return Some(operand.to_string());
    }
    let mut it = m.split_whitespace();
    let kind = it.next().unwrap_or("");
    let amount = it.next().and_then(parse_imm_i);
    match (kind, amount) {
        ("lsl", Some(n)) | ("lsr", Some(n)) | ("asr", Some(n)) => {
            if let Some(v) = parse_imm_i(operand) {
                // 立即数 + 常量移位：直接给出折叠后的值（硬件语义是精确的）
                let folded = match kind {
                    "lsl" => v.wrapping_shl(n as u32),
                    "lsr" => ((v as u64) >> n) as i64,
                    _ => v >> n,
                };
                return Some(format!("{folded:#x}"));
            }
            let sym = match kind {
                "lsl" => "<<",
                "lsr" => ">>",
                _ => ">>" ,
            };
            Some(format!("({operand} {sym} {n})"))
        }
        // 扩展修饰（零/符号扩展）不建模成表达式——写成注释，别编造语义
        ("uxtw" | "sxtw" | "uxtb" | "sxtb" | "uxth" | "sxth", amt) => {
            let tail = amt.map(|n| format!(" {n}")).unwrap_or_default();
            Some(format!("({operand} /* {kind}{tail} */)"))
        }
        // 认不出的第 4 段（例如 x86 三操作数的第二个值）**不能**塞进括号里：
        // `(mem(rax) 0x48)` 是语法错误。只有确认是移位/扩展关键字才折叠。
        _ => Some(operand.to_string()),
    }
}

/// 条件取反：只翻转**认得出的比较关系**，其余用 `!(...)` 包裹（不猜语义）。
fn negate_cond(c: &str) -> String {
    // 两字符关系先判，避免 `<=` 被 `<` 抢先匹配
    const NEG: &[(&str, &str)] = &[
        (" == ", " != "),
        (" != ", " == "),
        (" <= ", " > "),
        (" >= ", " < "),
        (" < ", " >= "),
        (" > ", " <= "),
    ];
    let t = c.trim();
    if let Some(inner) = t.strip_prefix("!(").and_then(|x| x.strip_suffix(')')) {
        return inner.to_string();
    }
    for (a, b) in NEG {
        if t.contains(a) {
            return t.replacen(a, b, 1);
        }
    }
    format!("!({t})")
}

/// 内存操作数 → **合法 Dart 表达式**。
///
/// 机器语法（`[x2, #0x3f]`、`[SP, #-0x10]!`）进不了 Dart：`[` 开头是列表字面量、
/// `#` 后必须是标识符、`!` 也不是后缀运算符。实测一个真实应用里有 14 万条
/// `expected_token` 就是这些字符带来的。所以：
/// * 栈基址（`[FP, #-8]`/`[SP, #0x10]`）→ `local_m8`（帧内局部槽，`m` 前缀表示负偏移）；
/// * 其它基址（`[x2, #0x3f]` = 堆对象字段）→ `mem(x2, 0x3f)`，读作「这段内存」——
///   语义仍是"不猜"，只是把机器写法换成能解析的函数调用。
fn mem_parts(operand: &str) -> MemOperand {
    let t = operand.trim();
    // 取第一个 `[` 到最后一个 `]` 之间的内容：x86 的写法带尺寸前缀
    // （`qword ptr [rbx + 0x18]`），只 strip_prefix('[') 会整段落空，
    // 于是 `qword ptr [...]` 被当成一个参数塞进 mem()，再被后置清洗包一层 → `mem(mem(..))`。
    let inner = match (t.find('['), t.rfind(']')) {
        (Some(a), Some(b)) if b > a => &t[a + 1..b],
        _ => t,
    };
    let inner = inner.trim();
    let parts: Vec<String> = split_operands(inner)
        .iter()
        .map(|x| x.trim().trim_end_matches('!').trim().to_string())
        .collect();
    let stack = matches!(
        parts.first().map(|s| s.as_str()).unwrap_or(""),
        "FP" | "SP"
    );
    // raw 只在「地址都拆不出来」的兜底分支里用（见 mem_write）
    let _ = &parts;
    MemOperand { parts, stack, raw: t.to_string() }
}

struct MemOperand {
    parts: Vec<String>,
    stack: bool,
    raw: String,
}

impl MemOperand {
    /// 栈槽 → `local_m8`（Dart 合法标识符）；否则 None
    fn local_name(&self) -> Option<String> {
        if !self.stack {
            return None;
        }
        let off = self.parts.get(1).map(|s| s.as_str()).unwrap_or("0");
        Some(local_ident(off))
    }
    /// 参数列表（丢掉 `#`），并把 arm64 的寻址修饰折进表达式：
    /// `[x21, x0, lsl #3]` → `x21, (x0 << 3)`；`[x0, w1, uxtw #2]` → `x0, w1 /* uxtw 2 */`
    /// （`lsl 3` 这种尾巴原样留在参数里会被 Dart 当成语法错误）。
    fn args(&self) -> String {
        let mut out: Vec<String> = Vec::new();
        let mut i = 0usize;
        while i < self.parts.len() {
            let p = self.parts[i].trim().trim_start_matches('#').to_string();
            let mut it = p.split_whitespace();
            let kind = it.next().unwrap_or("");
            let amt = it.next().map(|x| x.trim_start_matches('#').to_string());
            let is_mod = matches!(
                kind,
                "lsl" | "lsr" | "asr" | "uxtw" | "sxtw" | "uxtb" | "sxtb" | "uxth" | "sxth"
            );
            if is_mod && i > 0 {
                let prev = out.pop().unwrap_or_default();
                let sym = match kind {
                    "lsl" => "<<",
                    "lsr" | "asr" => ">>",
                    _ => "",
                };
                if !sym.is_empty() {
                    match &amt {
                        Some(a) => out.push(format!("({prev} {sym} {a})")),
                        None => out.push(prev),
                    }
                } else {
                    // 扩展类修饰：数值折叠不了，保留成注释（Dart 里 `/* .. */` 可放在实参位置）
                    match &amt {
                        Some(a) => out.push(format!("{prev} /* {kind} {a} */")),
                        None => out.push(prev),
                    }
                }
            } else {
                out.push(p);
            }
            i += 1;
        }
        out.join(", ")
    }
}

#[cfg(test)]
mod literal_tests {
    use super::dart_literal;

    /// 池里的字符串要变成**合法 Dart 字面量**：每个元字符都得转义。
    /// `$` 那条是真机应用里踩出来的——`"$IsolateException"` 不转义就是插值，
    /// `dart analyze` 直接报 undefined_identifier。
    #[test]
    fn escapes_dart_string_metacharacters() {
        assert_eq!(dart_literal("plain").as_deref(), Some("\"plain\""));
        assert_eq!(dart_literal("a\"b").as_deref(), Some("\"a\\\"b\""));
        assert_eq!(dart_literal("a\\b").as_deref(), Some("\"a\\\\b\""));
        // 换行要「大部分可打印」才会走到转义分支（纯控制字符整体被拒，见下个用例）
        assert_eq!(dart_literal("abcd\n").as_deref(), Some("\"abcd\\n\""));
        assert_eq!(dart_literal("$IsolateException").as_deref(), Some("\"\\$IsolateException\""));
        assert_eq!(dart_literal("${x}").as_deref(), Some("\"\\${x}\""));
    }

    /// 非可打印 ASCII 与二进制垃圾不进产物（保持「导出物零非 ASCII」）
    #[test]
    fn rejects_binary_and_non_ascii() {
        assert!(dart_literal("中文").is_none());
        assert!(dart_literal("\u{1}\u{2}\u{3}").is_none());
    }
}

/// 名字 → Dart 合法标识符。Dart 的类名里会有 `&`（mixin application，如
/// `Set&_LinkedHashBase&SetMixin`）与 `<`/`>`（泛型实参），这些字符在 Dart 源码里是
/// **运算符**——`Set&_X_while()` 会解析成 `Set & _X_while()`，直接编译错误。
/// 产物里把非法字符统一换成 `_`，并把数字开头补 `_` 前缀。
/// 注意：functions.txt / asm/ 等**数据产物保持原始名字**，只有 dart/ 需要合法标识符。
pub(crate) fn dart_ident(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '$' {
                c
            } else {
                '_'
            }
        })
        .collect();
    // 连续下划线收敛成一个（`_anon` + `&` 之类会叠出很多）
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    if out.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(true) {
        out.insert(0, '_');
    }
    // 名字本身是保留字时要让开：`dynamic rethrow() { .. }` 连解析都过不去
    if is_dart_keyword(&out) {
        out.push('_');
    }
    // 也不能撞上文件顶部那段伪运行时的声明（否则 duplicate_definition）
    if PSEUDO_FUNCS.iter().any(|(n, _)| *n == out) || WIDTH_NAMES.contains(&out.as_str()) {
        out.push('_');
    }
    out
}

/// `#-0x10` / `-8` / `0x10` → `local_m10` / `local_m8` / `local_10`
fn local_ident(off: &str) -> String {
    let o = off.trim().trim_start_matches('#');
    let neg = o.starts_with('-');
    let mag = o.trim_start_matches('-').trim_start_matches("0x");
    if neg {
        format!("local_m{mag}")
    } else {
        format!("local_{mag}")
    }
}

/// 内存读 → 合法表达式。
/// 基址是对象池（`PP` 或已被折叠成 `(PP + 0xb000)`）且偏移命中池表时，直接写成条目的值
/// ——这是**值恢复**：字符串常量、立即数在伪代码里直接可见。
fn mem_read(rl: &Roles, operand: &str) -> String {
    let m = mem_parts(operand);
    if let Some(l) = m.local_name() {
        return l;
    }
    if let Some(v) = pool_value(rl, &m) {
        return v;
    }
    format!("mem({})", m.args())
}

/// 池偏移 = 基址里的 PP 加数 + 位移。三种写法都要认：
/// * `[PP, #0x2d8]`（arm64 常见，基址与位移分开）；
/// * `[(PP + 0xb000), #0x778]`（adrp/add 折叠后基址带加数）；
/// * `[PP + 0x17f7]`（x64：池指针**带 tag**，偏移是 `条目偏移 - 1`，且写在一个操作数里）。
///
/// 带 tag 的情况不靠平台知识判断，直接 `off` 与 `off + 1` 各试一次——池条目间距 8 字节，
/// 相邻两个都是条目的概率为零，不会误命中。
fn pool_value(rl: &Roles, m: &MemOperand) -> Option<String> {
    let key = pool_key(rl, m)?;
    let v = rl.pool.get(&key)?.clone();
    // 字符串字面量后面留一个池偏移注释：`x0 = "key" /* pp+0x78 */`——
    // 值可以直接读，但读者仍能顺着偏移回到 pp.txt 对照原始条目。
    if v.starts_with('"') {
        return Some(format!("{v} /* pp+{key:#x} */"));
    }
    // 非字符串对象条目只带一个类型注释（`/* Field */`）：它自己不是表达式，
    // 直接当值会把产物写成 `x9 = /* Field */;`（语法错误）——补上内存读法。
    if v.starts_with("/*") {
        return Some(format!("mem({}) {v}", m.args()));
    }
    Some(v)
}

/// 这条内存操作数读的是哪个池槽。
///
/// 从 `pool_value` 里抽出来，是为了让 `dae findrefs` 与反编译产物**共用同一份解析**：
/// 产物里 `x0 = "Hello" /* pp+0x17f8 */` 那个偏移，和 findrefs 报出来的偏移，
/// 必须是同一个函数算出来的——这样「findrefs 的每个命中都能在 dart/ 里找到对应注释」
/// 就成了可断言的判据（门禁盯着），而不是靠人相信。
fn pool_key(rl: &Roles, m: &MemOperand) -> Option<u64> {
    if rl.pool.is_empty() {
        return None;
    }
    let (delta, disp) = pool_operand(m)?;
    for cand in [delta + disp, delta + disp + 1] {
        if cand < 0 {
            continue;
        }
        let key = cand as u64;
        if rl.pool.contains_key(&key) {
            return Some(key);
        }
    }
    None
}

/// 从内存操作数里析出 (PP 加数, 位移)；基址不是池指针时返回 None。
fn pool_operand(m: &MemOperand) -> Option<(i64, i64)> {
    let parts: Vec<String> = m
        .parts
        .iter()
        .map(|p| p.trim().trim_start_matches('#').trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    let parse_i = |t: &str| -> Option<i64> {
        let t = t.trim();
        let neg = t.starts_with('-');
        let body = t.trim_start_matches('-').trim_start_matches("0x");
        if body.is_empty() || !body.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let v = i64::from_str_radix(body, 16).ok()?;
        Some(if neg { -v } else { v })
    };
    // 基址段：要么就是 `PP`，要么是 `PP + 0x..` / `(PP + 0x..)`
    let base_of = |t: &str| -> Option<i64> {
        let t = t.trim();
        let inner = t.strip_prefix('(').and_then(|x| x.strip_suffix(')')).unwrap_or(t);
        if inner.trim() == "PP" {
            return Some(0);
        }
        let (a, b) = inner.split_once('+')?;
        if a.trim() != "PP" {
            return None;
        }
        // 加数可能是 `0xb, 0x12`（lsl 折叠后）——取第一个可解析的
        for tok in b.split(',') {
            if let Some(v) = parse_i(tok) {
                return Some(v);
            }
        }
        None
    };
    match parts.len() {
        1 => {
            // `PP + 0x17f7`：一个操作数里既带基址又带位移
            let t = parts[0].trim();
            let inner = t.strip_prefix('(').and_then(|x| x.strip_suffix(')')).unwrap_or(t);
            let (a, b) = inner.split_once('+')?;
            let delta = base_of(a)?;
            let disp = parse_i(b)?;
            Some((delta, disp))
        }
        _ => {
            let delta = base_of(&parts[0])?;
            let disp = parse_i(&parts[1])?;
            Some((delta, disp))
        }
    }
}

/// 写内存 → 合法语句（返回 `lvalue = value;` 或 `memSet(...);`）
fn mem_write(operand: &str, value: &str) -> String {
    let m = mem_parts(operand);
    if let Some(l) = m.local_name() {
        // 成对写（`stp x8, x1, [FP, #-0x50]`）的值是两个寄存器，不能写成
        // `local_m50 = x8, x1;`（Dart 没有逗号表达式）→ 走占位函数。
        if value.contains(',') {
            return format!("memSet({l}, {value});");
        }
        return format!("{l} = {value};");
    }
    if m.args().is_empty() {
        format!("memSet({value}); // {}\n", m.raw)
            .trim_end()
            .to_string()
    } else {
        format!("memSet({}, {value});", m.args())
    }
}

/// 取内存操作数的基址寄存器：`[SP, #0x10]!` → `SP`；`x0` → None。
fn mem_base(ops: &str) -> Option<&str> {
    let l = ops.find('[')?;
    let rest = &ops[l + 1..];
    let end = rest
        .find([',', ']'])
        .unwrap_or(rest.len());
    Some(rest[..end].trim())
}

/// 按顶层逗号切操作数，**不切方括号内**的逗号（`stp x0, x1, [SP, #0x10]` → 3 段）。
fn split_operands(ops: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, c) in ops.char_indices() {
        match c {
            '[' | '{' => depth += 1,
            ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                out.push(&ops[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&ops[start..]);
    out
}

/// 立即数（`#1` / `#-0x10` / `0x20` / 十进制都认）。**只解析，不猜类型。**
fn parse_imm_i(ops: &str) -> Option<i64> {
    let s = ops.trim().trim_start_matches('#').trim();
    let (neg, s) = match s.strip_prefix('-') {
        Some(r) => (true, r.trim()),
        None => (false, s),
    };
    let v: i64 = if let Some(h) = s.strip_prefix("0x") {
        let h: String = h.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        if h.is_empty() {
            return None;
        }
        u64::from_str_radix(&h, 16).ok()? as i64
    } else {
        let d: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
        if d.is_empty() {
            return None;
        }
        d.parse::<i64>().ok()?
    };
    Some(if neg { -v } else { v })
}

/// 分支/调用目标地址（无符号十六进制）
fn parse_addr(ops: &str) -> Option<u64> {
    let s = ops.trim().trim_start_matches('#');
    let h = s.strip_prefix("0x")?;
    let h: String = h.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    u64::from_str_radix(&h, 16).ok()
}

// ---------------------------------------------------------------- cfg

struct Block {
    start: u64,
    stmts: Vec<Stmt>,
    /// (条件, 目标块起始地址)；cond=None 表示无条件
    succs: Vec<(Option<String>, u64)>,
}

/// 切基本块。leader = 函数入口 + 跳转目标 + 跳转的下一条。
fn build_blocks(stmts: Vec<Stmt>) -> Vec<Block> {
    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    if let Some(s0) = stmts.first() {
        leaders.insert(s0.addr);
    }
    for (i, s) in stmts.iter().enumerate() {
        match &s.op {
            Op::Branch { target, .. } => {
                if *target != 0 {
                    leaders.insert(*target);
                }
                if let Some(nx) = stmts.get(i + 1) {
                    leaders.insert(nx.addr);
                }
            }
            Op::Return { .. } => {
                if let Some(nx) = stmts.get(i + 1) {
                    leaders.insert(nx.addr);
                }
            }
            _ => {}
        }
    }
    let mut blocks: Vec<Block> = Vec::new();
    for s in stmts {
        if leaders.contains(&s.addr) || blocks.is_empty() {
            blocks.push(Block {
                start: s.addr,
                stmts: Vec::new(),
                succs: Vec::new(),
            });
        }
        blocks.last_mut().unwrap().stmts.push(s);
    }
    // 连边
    let starts: Vec<u64> = blocks.iter().map(|b| b.start).collect();
    for (i, blk) in blocks.iter_mut().enumerate() {
        let last = blk.stmts.last().cloned();
        let next = starts.get(i + 1).copied();
        match last.map(|s| s.op) {
            Some(Op::Branch { cond, target }) => {
                if target != 0 && starts.contains(&target) {
                    blk.succs.push((cond.clone(), target));
                }
                if cond.is_some() {
                    if let Some(nx) = next {
                        blk.succs.push((None, nx));
                    }
                }
            }
            Some(Op::Return { .. }) | Some(Op::Abort(_)) | Some(Op::IndirectJump(_)) => {}
            // brk / br 也是终止符：不再造落空边（否则结构化器会把它当普通语句，
            // 并为「陷阱/分发之后的字节」连出一条不存在的后续）
            _ => {
                if let Some(nx) = next {
                    blk.succs.push((None, nx));
                }
            }
        }
    }
    blocks
}

// ---------------------------------------------------------------- emit

#[allow(clippy::too_many_arguments)]
fn emit_function(
    name: &str,
    blocks: &[Block],
    rl: &Roles,
    out: &mut String,
    raw: &str,
    chunks: &[u64],
    structured: &mut usize,
    fallback: &mut usize,
    fa: &FieldAnnot,
) {
    let mut s = Structurer::new(blocks, rl);
    let nodes = s.seq(0, None, 0);
    let reason = s.reason.clone();
    let mut unstructured = s.unstructured;
    // 预估容量：`body` 从 0 长起会反复 realloc + memmove（采样里 finish_grow 与
    // _platform_memmove 是前几名）。每条语句渲染后约 56 字节，按语句数一次给足。
    let n_stmts: usize = blocks.iter().map(|b| b.stmts.len()).sum();
    let mut body = String::with_capacity(n_stmts * 56 + 256);
    render_nodes(&nodes, 0, &mut body, &mut unstructured, fa);
    if unstructured {
        *fallback += 1;
        if std::env::var("DART_AOT_DEC_REASON").is_ok() {
            eprintln!(
                "[dec-reason] {} {}",
                if reason.is_empty() { "goto-emitted" } else { &reason },
                name
            );
        }
    } else {
        *structured += 1;
    }

    let _ = writeln!(out, "\n// {name}");
    if !chunks.is_empty() {
        // 共享尾块：这些语句在地址上不属于本函数的主范围，但控制流属于本函数
        let _ = writeln!(
            out,
            "// external chunks (shared code, addresses outside this function's range): {}",
            chunks
                .iter()
                .map(|c| format!("{c:#x}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let _ = writeln!(out, "// raw disassembly:");
    out.push_str("//");
    out.push_str(&raw.replace('\n', "\n//"));
    out.push('\n');
    if unstructured {
        let _ = writeln!(
            out,
            "// NOTE: control flow was not fully structured (goto kept) -- pseudocode only."
        );
    }
    let _ = writeln!(out, "dynamic {name}() {{");
    let mut declared: BTreeSet<String> = BTreeSet::new();
    for st in blocks.iter().flat_map(|b| b.stmts.iter()) {
        match &st.op {
            Op::Assign { dst, .. } => {
                let dst = sanitize_regs(dst);
                declared.insert(dst);
            }
            Op::Call { dst: Some(d), .. } => {
                let d = sanitize_regs(d);
                declared.insert(d);
            }
            Op::PairLoad { d1, d2, .. } => {
                for d in [d1, d2] {
                    let d = sanitize_regs(d);
                    declared.insert(d);
                }
            }
            _ => {}
        }
    }
    // 只声明**正文代码里**出现过的标识符：注释里出现的不算（`// frame: FP, LR, …` 会让
    // FP/BARRIER 这类角色寄存器挂着声明却无人读 → 每函数一条 unused_local_variable）。
    let code_only: String = body
        .lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    let words: std::collections::HashSet<&str> = code_only
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
        .filter(|t| !t.is_empty())
        .collect();
    let decls: Vec<String> = declared.into_iter().filter(|d| words.contains(d.as_str())).collect();
    for d in decls {
        let _ = writeln!(out, "  dynamic {d};");
    }
    out.push_str(&body);
    out.push_str("}\n");
}


/// 单个函数的原始反汇编文本（寄存器已按框架名替换、分支目标归一化）。
/// `disasm` 子命令在非 arm64 平台用它（arm64 走 asm.rs 的带 IL 分组版本）。
pub fn disasm_text(
    analyzer: &Analyzer,
    entry: u64,
    csize: u64,
    foff: u64,
) -> Result<String, String> {
    let is_arm64 = analyzer.platform.arch == "arm64";
    let rl = roles(analyzer);
    let cs = crate::disasm::build_cs(is_arm64)?;
    if foff as usize + csize as usize > analyzer.data.len() {
        return Err("函数字节超出文件范围".to_string());
    }
    let code = &analyzer.data[foff as usize..(foff + csize) as usize];
    let insns = cs
        .disasm_all(code, entry)
        .map_err(|e| format!("反汇编失败: {e}"))?;
    let mut out = String::with_capacity(insns.len() * 48);
    for ins in insns.iter() {
        let mnem = ins.mnemonic().unwrap_or("");
        let ops = mask_regs(&rl, ins.op_str().unwrap_or(""));
        let _ = writeln!(out, "  {:#x}: {mnem:<12} {ops}", ins.address());
    }
    if out.is_empty() {
        // 一个字节都解不出来时如实说明（例如整段都是填充）
        let _ = writeln!(out, "  // 无法反汇编（{csize} 字节）");
    }
    Ok(out)
}

/// 取出正文里用到的标识符（跳过 `//` 行注释与 `/* */` 块注释、字符串字面量）。
/// 用途：给「用到但本文件没定义」的名字补声明，让产物能过 `dart analyze`。
fn identifiers(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let bytes: Vec<char> = text.chars().collect();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        // 注释
        if c == '/' && bytes.get(i + 1) == Some(&'/') {
            while i < bytes.len() && bytes[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && bytes.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == '*' && bytes[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        // 字符串字面量
        if c == '\'' || c == '"' {
            let q = c;
            i += 1;
            while i < bytes.len() && bytes[i] != q {
                if bytes[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            continue;
        }
        // 数字字面量要整段吃掉：`0x5b30` 里的 `x` 会被误当成标识符开头
        // （曾收出 `x5b30`/`x838` 这类幽灵名字塞进声明表）
        if c.is_ascii_digit() {
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == '.' || bytes[i] == '_')
            {
                i += 1;
            }
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' || c == '$' {
            let mut id = String::new();
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == '_' || bytes[i] == '$')
            {
                id.push(bytes[i]);
                i += 1;
            }
            out.insert(id);
            continue;
        }
        i += 1;
    }
    out
}

/// Dart **保留字**：既不能出现在 `dynamic <name>;` 的声明列表里，也不能当函数名。
/// 注意不要把 `print`/`Object`/`String`/`List` 这类**内建标识符**混进来——它们可以
/// 当变量名用（实测 `dynamic print; dynamic Object, List;` 过分析），把它们排除在外
/// 反而会让 `print()` 撞上 dart:core 里那个要 1 个参数的 print（实测每份产物都报）。
fn is_dart_keyword(w: &str) -> bool {
    matches!(
        w,
        "abstract" | "as" | "assert" | "async" | "await" | "base" | "break" | "case" | "catch"
            | "class" | "const" | "continue" | "covariant" | "default" | "deferred" | "do"
            | "dynamic" | "else" | "enum" | "export" | "extends" | "extension" | "external"
            | "factory" | "false" | "final" | "finally" | "for" | "get" | "hide" | "if"
            | "implements" | "import" | "in" | "interface" | "is" | "late" | "library" | "mixin"
            | "new" | "null" | "of" | "on" | "operator" | "part" | "required" | "rethrow"
            | "return" | "sealed" | "set" | "show" | "static" | "super" | "switch" | "sync"
            | "this" | "throw" | "true" | "try" | "typedef" | "var" | "void" | "when" | "while"
            | "with" | "yield"
    )
}

/// 伪运行时：把机器层概念写成可解析的 Dart 占位
const PSEUDO_FUNCS: &[(&str, &str)] = &[
    ("mem", "dynamic mem(dynamic a, [dynamic b, dynamic c, dynamic d]) => null;"),
    ("memSet", "dynamic memSet(dynamic a, [dynamic b, dynamic c, dynamic d]) => null;"),
    ("memRead2", "dynamic memRead2(dynamic a, [dynamic b, dynamic c, dynamic d]) => null;"),
    ("gotoIndirect", "dynamic gotoIndirect(dynamic a) => null;"),
    ("convert", "dynamic convert(dynamic a) => null;"),
    ("mul", "dynamic mul(dynamic a) => null;"),
    ("addCarry", "dynamic addCarry(dynamic a, dynamic b) => null;"),
    ("subBorrow", "dynamic subBorrow(dynamic a, dynamic b) => null;"),
    ("toIntFloor", "dynamic toIntFloor(dynamic a) => null;"),
    ("toIntCeil", "dynamic toIntCeil(dynamic a) => null;"),
    ("toIntRound", "dynamic toIntRound(dynamic a) => null;"),
    ("xchg", "dynamic xchg(dynamic a, dynamic b) => null;"),
    ("idiv", "dynamic idiv(dynamic a) => null;"),
    ("mulHigh", "dynamic mulHigh(dynamic a) => null;"),
    ("condFlag", "bool condFlag(String cc) => false;"),
    ("clz", "dynamic clz(dynamic a) => null;"),
    ("stxr", "dynamic stxr(dynamic a, [dynamic b, dynamic c, dynamic d]) => null;"),
    ("callIndirect", "dynamic callIndirect(dynamic a) => null;"),
    ("gotoLabel", "dynamic gotoLabel(dynamic a) => null;"),
    ("addr", "dynamic addr(dynamic a) => null;"),
    ("abort", "dynamic abort([dynamic a]) => null;"),
    ("sqrt", "dynamic sqrt(dynamic a) => null;"),
    ("abs", "dynamic abs(dynamic a) => null;"),
    ("max", "dynamic max(dynamic a, dynamic b) => null;"),
    ("min", "dynamic min(dynamic a, dynamic b) => null;"),
    ("toFloat", "dynamic toFloat(dynamic a) => null;"),
    ("toFloatUnsigned", "dynamic toFloatUnsigned(dynamic a) => null;"),
    ("toInt", "dynamic toInt(dynamic a) => null;"),
    ("toIntUnsigned", "dynamic toIntUnsigned(dynamic a) => null;"),
    ("toDouble", "dynamic toDouble(dynamic a) => null;"),
    // 子寄存器扩展（arm64 `sxtw w1, w2`）：占位函数而非 `as` 转型
    ("sxtb", "dynamic sxtb(dynamic a) => null;"),
    ("sxth", "dynamic sxth(dynamic a) => null;"),
    ("sxtw", "dynamic sxtw(dynamic a) => null;"),
    ("uxtb", "dynamic uxtb(dynamic a) => null;"),
    ("uxth", "dynamic uxth(dynamic a) => null;"),
    ("uxtw", "dynamic uxtw(dynamic a) => null;"),
];

/// 位宽/扩展名（`as u8`、`as sxtw` 里的类型位）→ `typedef ... = int;`
const WIDTH_NAMES: &[&str] = &[
    "u8", "u16", "u32", "i8", "i16", "i32",
];

/// 文件前导：伪运行时 + 用到但本文件没定义的标识符声明。
/// 这一步是「产物能过 `dart analyze`」的关键：寄存器（x0/PP/THR）、跨库调用目标、
/// 机器层占位函数都不是 Dart 内建名字，不声明就是几万条 undefined_identifier。
/// 正文起始标记：`render_one_library` 在每个库正文的最前面写这一行，前导声明在它之前。
/// 合并多个库的输出时用它把「前导」与「正文」切开（见 [`split_rendered`]）。
pub const BODY_MARKER: &str = "// dae decompiler output -- pseudocode that parses as Dart";

/// 把 `render` 产出的一份文本切成 `(前导声明, 正文)`。找不到标记时返回 `None`——
/// 调用方应原样保留，不猜、不丢内容。
pub fn split_rendered(text: &str) -> Option<(&str, &str)> {
    let k = text.find(BODY_MARKER)?;
    Some((&text[..k], &text[k..]))
}

/// 按**合并后的正文**重算一份前导声明。
///
/// 为什么需要它：`getclass` / `getmethod` / `decompile` 的一个目标可能命中**多个库**
/// （混淆过的短类名尤其常见——Reqable 上随机抽 100 个类，**45 个命中 ≥2 个库**），
/// 而 `render` 是逐库出「前导 + 正文」的，直接拼接就得到多份前导，
/// `mem`/`memSet`/`gotoLabel` 这些占位函数于是重复定义，产物过不了 `dart analyze`
/// （`duplicate_definition`）。
///
/// 也**不能**「只留第一份前导、丢掉其余」：A 库的前导是按 A 的正文算的，它会把
/// **B 库定义的函数**声明成 `dynamic X;`（收窄产物里跨库调用就是这么处理的），
/// 与 B 的 `dynamic X() {}` 撞成 `duplicate_definition`。所以必须重算。
///
/// 「已定义的函数名」从正文里扫出来：发射形态固定是 `dynamic NAME() {`（行尾是 `{`），
/// 而前导里的占位声明是 `… => null;`、变量声明是 `dynamic a, b;`（无括号），都不会误判。
pub fn dart_preamble_for(bodies: &str) -> String {
    let mut defined: BTreeSet<String> = BTreeSet::new();
    for line in bodies.lines() {
        let Some(rest) = line.strip_prefix("dynamic ") else { continue };
        if !line.trim_end().ends_with('{') {
            continue;
        }
        let Some(i) = rest.find('(') else { continue };
        let n = rest[..i].trim();
        if !n.is_empty()
            && n.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
        {
            defined.insert(n.to_string());
        }
    }
    dart_preamble(bodies, &defined)
}

fn dart_preamble(body: &str, defined: &BTreeSet<String>) -> String {
    let used = identifiers(body);
    let mut vars: Vec<&String> = used
        .iter()
        .filter(|id| {
            !defined.contains(*id)
                && !is_dart_keyword(id)
                && !PSEUDO_FUNCS.iter().any(|(n, _)| n == id)
                && !WIDTH_NAMES.contains(&id.as_str())
        })
        .collect();
    vars.sort();
    let mut out = String::with_capacity(256 + vars.len() * 12);
    let _ = writeln!(
        out,
        "// ---------------------------------------------------------------------------"
    );
    let _ = writeln!(
        out,
        "// Pseudo-runtime declarations. dae output is pseudocode, but it must also parse"
    );
    let _ = writeln!(
        out,
        "// and analyse as Dart: these names stand in for the machine-level concepts"
    );
    let _ = writeln!(
        out,
        "// (memory access, indirect calls, unwinding) and for the registers the code"
    );
    let _ = writeln!(
        out,
        "// touches, which are not Dart built-ins."
    );
    let _ = writeln!(
        out,
        "// ---------------------------------------------------------------------------"
    );
    for (_, decl) in PSEUDO_FUNCS {
        let _ = writeln!(out, "{decl}");
    }
    for w in WIDTH_NAMES {
        let _ = writeln!(out, "typedef {w} = int;");
    }
    if !vars.is_empty() {
        let _ = writeln!(out);
        // 每行都必须是**完整的**声明：`dynamic a, b, c;`。换行后只写裸名字
        // （早期写法）会让整块变成语法错误。
        let mut group: Vec<&str> = Vec::new();
        let mut width = 0usize;
        for v in vars.iter() {
            if width + v.len() + 2 > 88 && !group.is_empty() {
                let _ = writeln!(out, "dynamic {};", group.join(", "));
                group.clear();
                width = 0;
            }
            group.push(v.as_str());
            width += v.len() + 2;
        }
        if !group.is_empty() {
            let _ = writeln!(out, "dynamic {};", group.join(", "));
        }
    }
    out.push('\n');
    out
}

/// 外部代码块（function chunk）：Dart AOT 会合并相同代码，于是某函数的分支目标会落在
/// **别的函数的字节范围里**（实测 2.13.4：`Iterable.get_isNotEmpty` 跳到 `map` 范围内的
/// 共享尾块，再跳回自己）。IDA/LLVM 把这种块当成本函数的一部分。
///
/// 纪律：只纳入「不是已知函数入口」的目标，每函数限块数/总字节数，遇到终止符
/// （ret/ud2/hlt）或跳回本函数主范围就收尾——**绝不因此把别的函数吞进来**。
const CHUNK_MAX_CHUNKS: usize = 8;
/// 控制流嵌套层数上限（见 `Structurer::seq` 的说明：钻太深会让产物过不了 Dart 解析）
const MAX_STRUCT_DEPTH: usize = 10;
const CHUNK_MAX_BYTES: usize = 256;

fn lift_chunks(
    cs: &Capstone,
    analyzer: &Analyzer,
    rl: &Roles,
    stmts: &[Stmt],
    is_arm64: bool,
    names: &BTreeMap<u64, String>,
) -> (Vec<Stmt>, Vec<u64>) {
    let Some(first) = stmts.first().map(|s| s.addr) else {
        return (Vec::new(), Vec::new());
    };
    let last = stmts.last().map(|s| s.addr).unwrap_or(first);
    let known: BTreeSet<u64> = stmts.iter().map(|s| s.addr).collect();
    let mut targets: Vec<u64> = Vec::new();
    for st in stmts {
        if let Op::Branch { target, .. } = &st.op {
            if *target != 0 && (*target < first || *target > last) {
                targets.push(*target);
            }
        }
    }
    targets.sort_unstable();
    targets.dedup();
    let mut extra: Vec<Stmt> = Vec::new();
    let mut chunk_addrs: Vec<u64> = Vec::new();
    for t in targets {
        if chunk_addrs.len() >= CHUNK_MAX_CHUNKS {
            break;
        }
        // 目标是真函数入口 → 那是调用/尾调用，不该内联
        if names.contains_key(&t) {
            continue;
        }
        let foff = t + analyzer.slice_off;
        if foff as usize >= analyzer.data.len() {
            continue;
        }
        let want = CHUNK_MAX_BYTES.min(analyzer.data.len() - foff as usize);
        let code = &analyzer.data[foff as usize..foff as usize + want];
        let Ok(insns) = cs.disasm_all(code, t) else { continue };
        let mut keep: Vec<u8> = Vec::new();
        let mut end = t;
        for ins in insns.iter() {
            let mnem = ins.mnemonic().unwrap_or("").to_string();
            let addr = ins.address();
            // 收尾：终止符，或跳回主范围/已收录的地址（共享尾块通常是跳回自己）
            // 收尾：终止符，或**任何**跳转回到主范围/已收录地址（共享尾块的典型结尾
            // 是 `je <函数内的地址>`，只认无条件跳转会把下一个函数的代码也吞进来）
            let is_branch = matches!(
                mnem.as_str(),
                "b" | "jmp" | "ret" | "retq" | "ud2" | "hlt" | "int3"
            ) || mnem.starts_with("j")
                || mnem.starts_with("b.");
            let stops = matches!(mnem.as_str(), "ret" | "retq" | "ud2" | "hlt" | "int3")
                || (is_branch
                    && ins
                        .op_str()
                        .and_then(parse_addr)
                        .map(|x| (first..=last).contains(&x) || known.contains(&x))
                        .unwrap_or(false));
            let len = ins.bytes().len();
            if addr + len as u64 > t + want as u64 {
                break;
            }
            keep.extend_from_slice(ins.bytes());
            end = addr + len as u64;
            if stops {
                break;
            }
        }
        if end <= t {
            continue;
        }
        let (mut cs_stmts, _raw) = lift(cs, rl, &keep, t, is_arm64, names);
        // 块内不能出现与主范围重复的地址
        cs_stmts.retain(|s| !known.contains(&s.addr));
        if cs_stmts.is_empty() {
            continue;
        }
        chunk_addrs.push(t);
        extra.append(&mut cs_stmts);
    }
    (extra, chunk_addrs)
}

// ---------------------------------------------------------------- entry

pub fn write(
    analyzer: &Analyzer,
    libs: &LibGroups,
    out_dir: &Path,
) -> Result<DecompileStats, String> {
    let dir = out_dir.join("dart");
    // **流式落盘**：每渲染完一个库就立刻写出去，不再把 505 份文件全攒在 `Vec` 里。
    // 原来 `render` 返回 `Vec<(文件名, 正文)>`，material_3_demo 上那是 **63.2 MB 常驻**，
    // 而且 `full = preamble + of` 还会把最大的一份（4.2 MB）再拷一遍。
    // 反编译器跑在 8 个导出器**之后**，它们 freed 的页没还给 OS，所以这 63 MB 是叠在
    // 导出高水位上的——实测 `--decompile` 比不带它高 46 MB。
    //
    // 目录要**无条件预建**，即使一份 `.dart` 都不产：`hello_2.10.4.exe` /
    // `hello_2.7.2.exe` 这类只有对象层、没有指令表的快照按设计不产伪代码，
    // 而 `dart_valid.rs::full_scorecard` 仍然会对每个样本的 `dart/` 目录跑
    // `dart analyze`（0 文件 0 错误是合法结果，目录不存在才是错误）。
    // 曾把这行改成「写第一份时由 stream_writer 顺手建」，scorecard 立刻红：
    // `启动 dart analyze 失败（目录 …/dart）: No such file or directory`。
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建 dart 目录失败: {e}"))?;
    let stats = render_into(analyzer, libs, &|name, preamble, body| {
        use std::io::Write;
        let mut w = crate::export::stream_writer(&dir, name)?;
        w.write_all(preamble.as_bytes())
            .map_err(|e| format!("写 dart 文件失败: {e}"))?;
        w.write_all(body.as_bytes())
            .map_err(|e| format!("写 dart 文件失败: {e}"))?;
        crate::export::finish_writer(w, name)
    })?;
    Ok(stats)
}

/// 渲染但不落盘：返回 (文件名, 正文) 列表 + 统计。
/// 子命令要往 stdout 出伪代码，所以这一层仍然收集成 `Vec`；
/// **落盘走 [`render_into`]，不要走这里**（那会把全部产物常驻内存）。
pub fn render(
    analyzer: &Analyzer,
    libs: &LibGroups,
) -> Result<(Vec<(String, String)>, DecompileStats), String> {
    // sink 现在要能被多个线程调用（`Sync`），所以收集容器套一层 Mutex。
    // 这条路径服务的是 stdout 子命令，通常只渲染被选中的少数几个库，锁竞争可以忽略。
    let files: std::sync::Mutex<Vec<(String, String)>> = std::sync::Mutex::new(Vec::new());
    let stats = render_into(analyzer, libs, &|name, preamble, body| {
        let mut full = String::with_capacity(preamble.len() + body.len());
        full.push_str(preamble);
        full.push_str(body);
        files.lock().unwrap().push((name.to_string(), full));
        Ok(())
    })?;
    Ok((files.into_inner().unwrap(), stats))
}

/// 渲染并把每个库文件交给 `sink(文件名, 前导声明, 正文)`。
///
/// 前导声明必须在正文**全部**渲染完之后才能算（要知道用到了哪些标识符、定义了哪些函数），
/// 但输出顺序是「前导在前、正文在后」——所以 sink 拿到两段、由它决定怎么拼：
/// 落盘版按序 `write_all` 两次（零拷贝），收集版才需要合成一个 `String`。
pub fn render_into(
    analyzer: &Analyzer,
    libs: &LibGroups,
    sink: &(dyn Fn(&str, &str, &str) -> Result<(), String> + Sync),
) -> Result<DecompileStats, String> {
    // `DART_AOT_PROF=1`：分阶段计时。加它是因为 release 构建开了 LTO，
    // `sample` 拿不到 inclusive 归因（除 start 外最高符号只占 0.6%），
    // 靠剖析器猜已经错过两次，所以改成自己量。
    let prof = std::env::var("DART_AOT_PROF").is_ok();
    let t0 = std::time::Instant::now();
    let mut mark = t0;
    let lap = |label: &str, mark: &mut std::time::Instant| {
        if prof {
            eprintln!("[prof] {label:<28} {:>8.2}s", mark.elapsed().as_secs_f64());
        }
        *mark = std::time::Instant::now();
    };
    let is_arm64 = analyzer.platform.arch == "arm64";
    let rl = roles(analyzer);

    // 字段名：Field 簇（直接写着）+ 访问器名推断（隐式 getter/setter 的名字）。
    let fctx = {
        let rec = recover_fields(analyzer)?;
        FieldCtx { by_class_off: rec.by_class_off, word: analyzer.profile.word_size }
    };
    lap("recover_fields", &mut mark);

    // 入口地址 → 显示名（与产物里的函数标题一致，首见生效），供 `bl` 目标命名。
    //
    // ⚠️ 这张表必须按**未筛选的完整函数表**建，不能按传进来的 `libs` 建。
    // `libs` 是发射集合（`--lib` / `--app` / `getclass` 会把它收窄），而**调用目标的命名
    // 与「发射哪些函数」无关**：按收窄后的表建名字，会让每一个跨库调用退化成 `sub_0x…`。
    // 实测 testing_app：`Favorites.remove` 里的 `_favoriteItems.remove(itemNo)` 与
    // `notifyListeners()` 在全量反编译下是 `GrowableList_remove()` 与
    // `ChangeNotifier_notifyListeners()`，而 `--lib testing_app` 下变成
    // `sub_0x8a1b8()` / `sub_0x6d60()`——恰好把语义最重要的两个调用弄丢了，
    // 而「只看应用自有代码」正是 `--app` 推荐的用法。
    //
    // 全量导出时 `libs` 本来就等于完整表，所以这一改对全量产物**逐字节无影响**
    // （已用 `diff -rq` 验证）；只有收窄时命名变全。收窄后这些名字在本文件里没有定义，
    // 由 `dart_preamble` 声明成 `dynamic`，调用它是合法的动态调用，产物仍能过 `dart analyze`。
    let all_libs = analyzer.build_functions(true);
    let mut names: BTreeMap<u64, String> = BTreeMap::new();
    for (_lib, cls_map) in &all_libs {
        for (_cls, funcs) in cls_map {
            for f in funcs {
                if f.ep == 0 || names.contains_key(&f.ep) {
                    continue;
                }
                let n = dart_ident(
                    format!(
                        "{}_{}",
                        _cls.replace(['.', ':', '&', '<', '>'], "_"),
                        f.mangled
                    )
                    .trim_start_matches('_'),
                );
                names.insert(f.ep, n);
            }
        }
    }
    // 指令表里所有入口都补一个名字：有 Code 对象但没解析出名字的（匿名闭包等）
    // 用 `sub_0x...` 占位——`call 0x171018` 这种裸地址读起来无从下手，
    // 而 `call sub_0x171018` 至少表明「这是一个函数入口，只是没有名字」。
    // 「没有被 Code 对象认领」的表项 = stub（分配/类型测试/dispatch 桩）。分配 stub 的
    // 类名可以直接从它的序言解出来（callgraph 里那套、有零编造门禁），解出来就用在调用点上：
    // `call sub_0xfb68` → `call AllocationStub_UnsupportedError`。解不出的保持 `sub_0x..`。
    let claimed: BTreeSet<usize> = analyzer.func_eps.values().map(|(_, idx)| *idx).collect();
    let stub_eps: Vec<u64> = (0..analyzer.pc_offsets.len())
        .filter(|i| !claimed.contains(i))
        .filter_map(|i| analyzer.code_range(i).map(|(ep, _)| ep))
        .collect();
    for (ep, name) in crate::export::callgraph::alloc_stubs_at(analyzer, &stub_eps) {
        if let Some(n) = name {
            names.insert(ep, n);
        }
    }
    for idx in 0..analyzer.pc_offsets.len() {
        if let Some((ep, _)) = analyzer.code_range(idx) {
            names.entry(ep).or_insert_with(|| format!("sub_{ep:#x}"));
        }
    }
    lap(&format!("names+stubs ({} entries)", names.len()), &mut mark);
    let prof_t_main = std::time::Instant::now();
    use std::time::{Duration, Instant};
    let (mut p_lift, mut p_chunks, mut p_cfg, mut p_emit, mut p_pre) =
        (Duration::ZERO, Duration::ZERO, Duration::ZERO, Duration::ZERO, Duration::ZERO);
    let mut n_prof_fn = 0usize;

    // ---- 阶段 A（顺序、廉价）：定文件名 + 定「每个入口地址归哪个库渲染」 ----
    //
    // 这两件事都是**首见生效**，必须按 `libs` 的原始顺序做，否则产物会变：
    // - 文件名去重是大小写不敏感的，第二个撞名的库要加 `_2` 后缀；
    // - 代码共享（Dart 会把相同的 getter 体去重，一个机器码入口被多个 Function 对象引用）时，
    //   同一个 ep 只由**第一个遇到它的库**发射一次——原先靠跨库的 `seen: BTreeSet` 保证。
    // 预扫描把归属固定成 `owner: ep → 库序号`，阶段 B 就能按库并行而**输出逐字节不变**。
    // 成本是 O(函数数) 次哈希插入（material_3_demo 15 082 个）。
    let mut fnames: Vec<String> = Vec::with_capacity(libs.len());
    let mut ests: Vec<usize> = Vec::with_capacity(libs.len());
    let mut owner: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
    {
        let mut used: BTreeMap<String, u32> = BTreeMap::new();
        for (ji, (lib_name, cls_map)) in libs.iter().enumerate() {
            let mut file = if lib_name.is_empty() {
                "app".to_string()
            } else {
                lib_name.clone()
            }
            .replace(['/', '$', ':'], "_");
            if !file.ends_with(".dart") {
                file.push_str(".dart");
            }
            let k = file.to_lowercase();
            let fname = match used.get(&k) {
                Some(&n) => {
                    used.insert(k, n + 1);
                    format!("{}_{}.dart", &file[..file.len() - 5], n + 1)
                }
                None => {
                    used.insert(k, 1);
                    file.clone()
                }
            };
            fnames.push(fname);
            // 正文容量按**代码字节**预估，不按函数个数。
            //
            // 原来写的是 `n_fns * 768 + 4096`，而实测 material_3_demo：代码字节共 3.8 MB、
            // dart/ 产出 63.2 MB ⇒ 膨胀 **≈16.6 字节产物 / 字节机器码**（asm/ 是
            // 46.3 / 3.8 ≈ 12.2，正好对上 `asm.rs` 里已有的系数 12，互为交叉验证）。
            // 按个数估只给到 15 082 × 768 = 11.6 MB，**低估 5.4 倍** ⇒ 每个库的 String
            // 都要翻倍扩容好几次，峰值容量最多是成品的 2 倍。并发渲染时这是按线程数放大的，
            // 所以估准了在**任何并发度下都省内存**（取 18 略高于 16.6，宁可一次到位）。
            let mut est: usize = 4096;
            for (_cls, funcs) in cls_map {
                for f in funcs {
                    // 与原来的 `if f.ep == 0 || !seen.insert(f.ep)` 逐字等价：
                    // `||` 短路 ⇒ ep==0 时**不**占用归属
                    if f.ep == 0 {
                        continue;
                    }
                    match owner.entry(f.ep) {
                        std::collections::hash_map::Entry::Occupied(_) => continue,
                        std::collections::hash_map::Entry::Vacant(v) => {
                            v.insert(ji as u32);
                        }
                    }
                    // 只估真正会被本库发射的那些（共享入口归第一个认领它的库）
                    if let Some((_, csize)) = analyzer.code_range(f.idx) {
                        est += csize as usize * 18 + 96;
                    }
                }
            }
            ests.push(est);
        }
    }

    // ---- 阶段 B（并行）：每线程一个 capstone（它不是 Sync），按库取任务 ----
    //
    // 反编译器原先是**单线程**跑完 505 个库的：material_3_demo 上 render 合计 2.49s，
    // 占整次 `--decompile`（墙钟 3.0s）的绝大部分，而机器有 18 核。各库之间除了阶段 A
    // 那两项「首见生效」的归属外没有依赖，所以按库并行是安全的。
    // 并发度 = `n_threads()`（与 asm/callgraph 等导出器同一个口径：核数，上限 8）。
    //
    // 反编译的每线程工作集比其它导出器大：前导声明必须在正文渲染完之后才能算
    // （要知道用到了哪些标识符、定义了哪些函数），所以**一个库的正文必须整份驻留内存**，
    // 没法流式掉，而库的大小极不均匀（material_3_demo 最大的一份 4.2 MB，505 份共 63.2 MB）。
    // 实测 material_3_demo（15 082 函数，18 逻辑核 = 6 性能核 + 12 能效核）：
    //
    //   并发   墙钟(s)          峰值 RSS(MB)
    //   串行   2.98–3.05        181–200
    //   1      3.09             159.7   ← 流式落盘单独的收益
    //   2      1.83–1.90        175
    //   3      1.43–1.51        178.7
    //   4      1.23–1.25        205
    //   8      **0.96**         206–235  ← 取这档
    //   12     1.12–1.24        235–241
    //   18     1.08–1.15        267
    //
    // **8 是甜点，再往上两项都变差**：线程数超过性能核之后任务会落到能效核上，
    // 而共享队列里一个慢线程拿着大库就拖住收尾（12/18 线程反而比 8 慢 0.1–0.3 s），
    // 内存还按线程数线性涨。所以「默认拉满」在本项目里就是 `n_threads()`，不是核数原值。
    // 想换档位用 `DAE_DEC_THREADS`（不必改代码重编）。
    //
    // ⚠️ 并行**不改变产物一个字节**：文件名与「每个入口地址归哪个库」都在阶段 A
    // 按原始顺序预先定死，线程只是领取任务。已验：material_3_demo 1011 个文件在
    // 1/8 线程下 `diff -rq` 完全相同，另 6 个语料与串行版也逐字节一致。
    let n_threads = std::env::var("DAE_DEC_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or_else(crate::analyzer::n_threads)
        .min(libs.len().max(1));
    let next = std::sync::atomic::AtomicUsize::new(0);
    let err: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
    let merged: std::sync::Mutex<(DecompileStats, [Duration; 5], usize)> =
        std::sync::Mutex::new((
            DecompileStats {
                funcs: 0,
                blocks: 0,
                stmts: 0,
                structured: 0,
                fallback: 0,
                unmapped: 0,
                calls: 0,
                calls_named: 0,
            },
            [Duration::ZERO; 5],
            0,
        ));
    std::thread::scope(|scope| {
        for _ in 0..n_threads {
            scope.spawn(|| {
                let cs = match crate::disasm::build_cs(is_arm64) {
                    Ok(c) => c,
                    Err(e) => {
                        *err.lock().unwrap() = Some(e);
                        return;
                    }
                };
                loop {
                    if err.lock().unwrap().is_some() {
                        break;
                    }
                    let j = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if j >= libs.len() {
                        break;
                    }
                    let (lib_name, cls_map) = &libs[j];
                    match render_one_library(
                        analyzer,
                        &rl,
                        &fctx,
                        &names,
                        &cs,
                        is_arm64,
                        prof,
                        lib_name,
                        cls_map,
                        &fnames[j],
                        ests[j],
                        &owner,
                        j as u32,
                        sink,
                    ) {
                        Ok((st, pd, nf)) => {
                            let mut m = merged.lock().unwrap();
                            m.0.funcs += st.funcs;
                            m.0.blocks += st.blocks;
                            m.0.stmts += st.stmts;
                            m.0.structured += st.structured;
                            m.0.fallback += st.fallback;
                            m.0.unmapped += st.unmapped;
                            m.0.calls += st.calls;
                            m.0.calls_named += st.calls_named;
                            for (a, b) in m.1.iter_mut().zip(pd) {
                                *a += b;
                            }
                            m.2 += nf;
                        }
                        Err(e) => {
                            *err.lock().unwrap() = Some(e);
                            return;
                        }
                    }
                }
            });
        }
    });
    if let Some(e) = err.into_inner().unwrap() {
        return Err(e);
    }
    let (stats, mpd, mnf) = merged.into_inner().unwrap();
    p_lift += mpd[0];
    p_chunks += mpd[1];
    p_cfg += mpd[2];
    p_emit += mpd[3];
    p_pre += mpd[4];
    n_prof_fn += mnf;
/// 渲染**一个库**：返回它的前导声明与正文，由调用方决定落盘还是收集。
///
/// 从 `render_into` 的主循环里抽出来，是为了让各库能**并行**渲染——见 `render_into`
/// 阶段 A 的说明：文件名与「每个入口地址归哪个库」都已预先按原始顺序定死，
/// 所以这里没有任何跨库共享的可变状态（`defined` 是库内函数名去重，天然局部）。
///
/// `stats` / `p_*` / `n_prof_fn` 都是本函数内的局部量，由调用方合并；
/// `cs`（capstone）不是 `Sync`，必须**每线程一个**，所以由调用方传进来。
#[allow(clippy::too_many_arguments)]
fn render_one_library(
    analyzer: &Analyzer,
    rl: &Roles,
    fctx: &FieldCtx,
    names: &BTreeMap<u64, String>,
    cs: &capstone::Capstone,
    is_arm64: bool,
    prof: bool,
    lib_name: &str,
    cls_map: &[(String, Vec<crate::analyzer::FuncEntry>)],
    fname: &str,
    est: usize,
    owner: &std::collections::HashMap<u64, u32>,
    ji: u32,
    sink: &(dyn Fn(&str, &str, &str) -> Result<(), String> + Sync),
) -> Result<(DecompileStats, [std::time::Duration; 5], usize), String> {
    let mut stats = DecompileStats {
        funcs: 0,
        blocks: 0,
        stmts: 0,
        structured: 0,
        fallback: 0,
        unmapped: 0,
        calls: 0,
        calls_named: 0,
    };
    let (mut p_lift, mut p_chunks, mut p_cfg, mut p_emit, mut p_pre) =
        (Duration::ZERO, Duration::ZERO, Duration::ZERO, Duration::ZERO, Duration::ZERO);
    let mut n_prof_fn = 0usize;
    // 容量由 render_into 的预扫描按「代码字节 × 18」算好——见那里的说明
    let mut of = String::with_capacity(est);
    let _ = writeln!(of, "// dae decompiler output -- pseudocode that parses as Dart");
    let _ = writeln!(of, "// library: {lib_name}");
    let _ = writeln!(
        of,
        "// control flow is structured (if/else + loops) where possible; functions whose"
    );
    let _ = writeln!(
        of,
        "// control flow could not be structured keep a NOTE header and emit gotoLabel()."
    );
    let mut cnt = 0usize;
    // 同一文件内函数名去重：两个不同入口可能算出同一个名字（同一类的多个匿名闭包），
    // 而 Dart 里同名定义是编译错误（duplicate_definition）。
    let mut defined: BTreeSet<String> = BTreeSet::new();
    // 库内 ep 去重（与跨库的 `owner` 一起复刻原来那一个全局 `seen` 的语义）
    let mut seen_local: BTreeSet<u64> = BTreeSet::new();
    for (_cls, funcs) in cls_map {
        for f in funcs {
            // 与原来的 `if f.ep == 0 || !seen.insert(f.ep)` 等价，拆成两半：
            // - `owner` 是阶段 A 预扫描定死的**跨库**归属（首见生效，见 render_into）；
            // - `seen_local` 是**库内**去重。原来那一个 `seen` 同时干这两件事，
            //   只靠 owner 会漏掉库内重复：同一个库里有两条 FuncEntry 指向同一 ep
            //   （代码共享在库内也发生，如一批同体 getter）时，两条都会通过归属检查
            //   而各发射一次。实测 material_3_demo 因此多出 **285 个函数**
            //   （15 082 → 15 367）。它每个任务独有，并行下无竞争。
            if f.ep == 0 || owner.get(&f.ep).copied() != Some(ji) || !seen_local.insert(f.ep) {
                continue;
            }
            let Some((entry, csize)) = analyzer.code_range(f.idx) else {
                if std::env::var("DART_AOT_DEBUG_DEC").is_ok() {
                    eprintln!(
                        "[dbg-dec] skip ep={:#x} cls={:?} m={} idx={}",
                        f.ep, _cls, f.mangled, f.idx
                    );
                }
                continue;
            };
            let foff = entry + analyzer.slice_off;
            if foff as usize + csize as usize > analyzer.data.len() {
                continue;
            }
            // **带前瞻地反汇编**：code size 常常把函数截在最后一条指令中间
            // （x64 的多字节 NOP `66 2e 0f 1f 84 00 ..` 只进来前 4 字节时，
            // capstone 只能吐 `.byte`）。多给 16 字节，再只保留起点在范围内的语句。
            let look = 16usize;
            let end = ((foff as usize + csize as usize) + look).min(analyzer.data.len());
            let code = &analyzer.data[foff as usize..end];
            let _pt = Instant::now();
            let (mut stmts, mut raw) = lift(cs, rl, code, entry, is_arm64, names);
            if prof { p_lift += _pt.elapsed(); }
            let limit = entry + csize;
            stmts.retain(|s| s.addr < limit);
            // raw 注释块要按**同一边界**裁剪。上面那 16 字节前瞻是必要的
            // （code size 常把函数截在指令中间），但它取到的字节属于紧随其后的
            // 函数；`stmts` 一直有 retain，raw 漏了 ⇒ 每个函数的注释块尾部都多印
            // 几条**别人的指令**，读的人会把它算到本函数头上，产物也白白变大。
            // 实测 sample_arm64 `_Record.get_hashCode`：entry 0x49e12c + size 0x12c
            // ⇒ 边界 0x49e258，而注释块印到 0x49e264，多出的 `csetm x0, eq`
            // 属于下一个函数（`dae disasm` 的 IL 到 0x49e254 就结束，可对照）。
            clip_raw(&mut raw, limit);
            if stmts.is_empty() {
                if std::env::var("DART_AOT_DEBUG_DEC").is_ok() {
                    eprintln!("[dbg-dec] 空 lift: {_cls}.{} ep={:#x} entry={entry:#x} csize={csize}", f.mangled, f.ep);
                }
                continue;
            }
            // 共享尾块（跳进别的函数范围又跳回来）也算本函数的一部分
            let _pt = Instant::now();
            let (extra, chunks) = lift_chunks(cs, analyzer, rl, &stmts, is_arm64, names);
            if prof { p_chunks += _pt.elapsed(); }
            if !extra.is_empty() {
                stmts.extend(extra);
                stmts.sort_by_key(|s| s.addr);
            }
            let _pt = Instant::now();
            let blocks = build_blocks(stmts);
            if prof { p_cfg += _pt.elapsed(); }
            if prof { n_prof_fn += 1; }
            stats.stmts += blocks.iter().map(|b| b.stmts.len()).sum::<usize>();
            stats.blocks += blocks.len();
            for b in &blocks {
                for st in &b.stmts {
                    if let Op::Call { target: Some(_), resolved, .. } = &st.op {
                        stats.calls += 1;
                        if resolved.is_some() {
                            stats.calls_named += 1;
                        }
                    }
                }
            }
            let base = dart_ident(
                format!(
                    "{}_{}",
                    _cls.replace(['.', ':', '&', '<', '>'], "_"),
                    f.mangled
                )
                .trim_start_matches('_'),
            );
            let mut name = base.clone();
            let mut k = 2usize;
            while defined.contains(&name) {
                name = format!("{base}_{k}");
                k += 1;
            }
            defined.insert(name.clone());
            if std::env::var("DART_AOT_DEBUG_DEC").is_ok() {
                eprintln!("[dbg-dec] emit ep={:#x} entry={entry:#x} csize={csize} name={name}", f.ep);
            }
            let before = of.len();
            if std::env::var("DART_AOT_DEBUG_DEC").is_ok() && name.contains("get_result") {
                eprintln!("[dbg-dec] annotate name={name} cls={_cls:?} map_has={}", fctx.by_class_off.contains_key(&(_cls.to_string(), 0x18)));
            }
            let fa = FieldAnnot { class: _cls, ctx: fctx, rl };
            let _pt = Instant::now();
            emit_function(
                &name,
                &blocks,
                rl,
                &mut of,
                &raw,
                &chunks,
                &mut stats.structured,
                &mut stats.fallback,
                &fa,
            );
            if prof { p_emit += _pt.elapsed(); }
            // 未映射行只数**发射出去的**：原来的口径统计所有基本块，
            // 把永远走不到的块也算进去，产物一变就虚高（chunk 之后尤其明显）
            stats.unmapped += of[before..].matches("// unmapped:").count();
            cnt += 1;
        }
    }
    stats.funcs += cnt;
    // 前导声明要在正文全部渲染完之后算（要知道用到哪些标识符、定义了哪些函数）
    let _pt = Instant::now();
    let preamble = dart_preamble(&of, &defined);
    if prof { p_pre += _pt.elapsed(); }
    sink(fname, &preamble, &of)?;

    Ok((
        stats,
        [p_lift, p_chunks, p_cfg, p_emit, p_pre],
        n_prof_fn,
    ))
}

    if prof {
        let tot = prof_t_main.elapsed().as_secs_f64();
        eprintln!(
            "[prof] {:<28} {:>8.2}s",
            "主循环(lift+结构+渲染)",
            tot
        );
        // ⚠️ 各阶段是**跨线程累加的 CPU 时间**，而「主循环」是墙钟，所以并行渲染下
        // 下面的百分比会超过 100%（实测 lift 271% / emit 357%）——那是并发度的体现，
        // 不是计时错乱。想看单线程口径就 `DAE_DEC_THREADS=1`。
        for (l, d) in [
            ("  ├ lift (反汇编+IR)", p_lift),
            ("  ├ lift_chunks (共享尾块)", p_chunks),
            ("  ├ build_blocks (CFG)", p_cfg),
            ("  ├ emit_function (结构化+渲染)", p_emit),
            ("  └ dart_preamble (前导声明)", p_pre),
        ] {
            eprintln!(
                "[prof] {l:<28} {:>8.2}s  ({:>5.1}%)",
                d.as_secs_f64(),
                d.as_secs_f64() / tot.max(0.001) * 100.0
            );
        }
        eprintln!("[prof]   函数数={n_prof_fn}");
        eprintln!("[prof] {:<28} {:>8.2}s", "render 合计", t0.elapsed().as_secs_f64());
    }
    Ok(stats)
}
// ---------------------------------------------------------------- 字段名恢复
//
// AOT 把绝大多数 Field 对象丢了：`Precompiler::DropFields` 只在非 PRODUCT 构建保留
// 字段名，真机产物里通常只剩几十条（`@pragma("vm:entry-point")` 的那些）。两条
// **可证**的恢复路径，都不猜：
//
// 1. **Field 簇**（analyzer.fields_rec）：snapshot 直接写着名字，偏移由 Mint 值给出
//    （Smis 被并进 Mint 簇，值即字索引；字节偏移 = 字索引 × word_size）；
// 2. **访问器名**：`get:foo` / `set:foo` 的**访问器名里带字段名**（aotopsy 同法），
//    而访问器函数体只碰一个字段——「函数体里恰好一处字段形访问」就是可证条件，
//    两处以上直接放弃，不去猜哪一处是返回值。
//
// 注解只在**类内**成立：`mem(x1, #0x17)` 命名为 `_FutureListener.result`，说的是
// 「owner 类的这个偏移是 result」，没有声称 x1 就是该类实例。机器码里位移比字节偏移
// 小 1（tagged 折算），所以查表用 `disp + 1`。

/// 字段注解表：(类名, 字节偏移) → 字段名；`word` = 指针宽度
struct FieldCtx {
    by_class_off: BTreeMap<(String, u64), String>,
    word: u64,
}

impl FieldCtx {
    /// 一条 `mem(base, 0xNN)` 的位移 → 字节偏移（tagged 折算 + 字对齐）。
    /// 折不出来（负位移、非字对齐、0）就返回 None：宁可不注解。
    fn offset_of(&self, disp: i64) -> Option<u64> {
        if disp < 1 {
            return None;
        }
        let off = (disp + 1) as u64;
        if !off.is_multiple_of(self.word) {
            return None;
        }
        Some(off)
    }

    fn name(&self, class: &str, off: u64) -> Option<&str> {
        if class.is_empty() {
            return None;
        }
        self.by_class_off.get(&(class.to_string(), off)).map(|s| s.as_str())
    }
}

/// 字段名恢复结果（`dae fields` 与门禁共用这一份口径）。
pub struct RecoveredFields {
    /// (类名, 字节偏移) → 字段名
    pub by_class_off: BTreeMap<(String, u64), String>,
    /// 来自 Field 簇（snapshot 直接写着）的条数
    pub from_records: usize,
    /// 访问器名推断**新增**的条数（记录里已有的不重复计）
    pub from_accessors: usize,
    /// 两个来源**独立得到同一结论**的条数：访问器名与 Field 记录的 (类, 偏移, 名字)
    /// 完全一致的次数。这是本模块最强的自证：名字来自访问器名、偏移来自机器码位移，
    /// 与 snapshot 里直接写着的字段表逐条对上。掉下来就说明偏移换算或名字提取坏了。
    pub agreements: usize,
    /// 两个来源打架的条目：(类, 偏移, 记录名, 访问器名)。为空才健康。
    pub conflicts: Vec<(String, u64, String, String)>,
}

/// 恢复结果 → 导出行（`dae fields` / `text/fields.txt`）。
pub fn field_rows_of(analyzer: &Analyzer, rec: &RecoveredFields) -> Vec<FieldRow> {
    let mut from: BTreeMap<(String, u64), &'static str> = BTreeMap::new();
    for f in &analyzer.fields_rec {
        from.insert((f.class.clone(), f.off), "rec");
    }
    let mut rows: Vec<FieldRow> = rec
        .by_class_off
        .iter()
        .map(|((class, off), name)| FieldRow {
            class: class.clone(),
            name: name.clone(),
            source: from.get(&(class.clone(), *off)).copied().unwrap_or("accessor"),
            off: *off,
        })
        .collect();
    rows.sort_by(|a, b| (&a.class, a.off).cmp(&(&b.class, b.off)));
    rows
}

/// 字段名恢复：Field 簇 + 访问器名推断。
/// 压缩指针模式下的位移折算未经实测，那种情况下只给记录、不跑访问器推断。
pub fn recover_fields(analyzer: &Analyzer) -> Result<RecoveredFields, String> {
    let is_arm64 = analyzer.platform.arch == "arm64";
    let rl = roles(analyzer);
    let cs = crate::disasm::build_cs(is_arm64)?;
    let word = analyzer.profile.word_size;
    let mut by_class_off = analyzer.field_by_class_off.clone();
    let from_records = by_class_off.len();
    let mut from_accessors = 0usize;
    let mut agreements = 0usize;
    let mut conflicts: Vec<(String, u64, String, String)> = Vec::new();
    // 压缩指针构建的位移折算已实测核对（真机产物：`_FutureListener.result` 在压缩词宽下
    // 是词 3 → 字节 12 → 位移 11；桌面词宽下同名字段是词 3 → 24 → 位移 23），两种词宽
    // 都走同一套「Mint 字索引 × word_size − 1」链条，故不再按变体关掉。
    if true {
        let probe = FieldCtx { by_class_off: BTreeMap::new(), word };
        for (k, v) in accessor_fields(&cs, analyzer, &rl, &probe) {
            match by_class_off.get(&k) {
                Some(prev) if prev != &v => conflicts.push((k.0.clone(), k.1, prev.clone(), v)),
                Some(_) => agreements += 1,
                None => {
                    from_accessors += 1;
                    by_class_off.insert(k, v);
                }
            }
        }
    }
    let rec = RecoveredFields { by_class_off, from_records, from_accessors, agreements, conflicts };
    if std::env::var("DART_AOT_DEBUG_FIELDS").is_ok() {
        eprintln!(
            "[dbg-fields-total] 记录 {} 条 + 访问器新增 {} 条 = {} 条；两源一致 {} 条；冲突 {} 条",
            rec.from_records, rec.from_accessors, rec.by_class_off.len(), rec.agreements,
            rec.conflicts.len()
        );
        for (c, off, a, b) in &rec.conflicts {
            eprintln!("[dbg-fields-total] 冲突 {c} off={off:#x}: 记录={a} 访问器={b}");
        }
    }
    Ok(rec)
}

/// 内存操作数 → (基址, 位移原文)。两种写法都要认：
/// * arm64：`[x1, #0x17]` —— 基址与位移是两个逗号分隔的操作数；
/// * x64：`[rdi + 0x17]` —— 基址与位移挤在**一个**操作数里（`+` 分隔）。
///
/// 三段式（`[base, index, lsl #3]`）返回 None：那是数组元素寻址，不是字段。
fn base_disp(inner: &str) -> Option<(String, String)> {
    // 顶层（括号深度 0）的最后一个 `+` 处切开——`(mem(FP - 8)) + 7` 要切在外层那个 `+`
    let split_plus = |t: &str| -> Option<(String, String)> {
        let b: Vec<char> = t.chars().collect();
        let mut depth = 0i32;
        let mut cut: Option<usize> = None;
        for (i, c) in b.iter().enumerate() {
            match c {
                '(' | '[' => depth += 1,
                ')' | ']' => depth -= 1,
                '+' if depth == 0 => cut = Some(i),
                _ => {}
            }
        }
        let cut = cut?;
        let byte = t.char_indices().nth(cut)?.0;
        Some((t[..byte].to_string(), t[byte + 1..].to_string()))
    };
    // 基址归一：剥平衡外括号；剩下的要么是裸标识符，要么是嵌套的 `mem(...)`（本身会被递归注解）
    let norm = |base: &str| -> Option<String> {
        let mut b = base.trim();
        while let Some(x) = b.strip_prefix('(').and_then(|y| y.strip_suffix(')')) {
            b = x.trim();
        }
        if b.is_empty() || b.contains('+') || b.contains(',') {
            return None;
        }
        if b.starts_with("mem(") && b.ends_with(')') {
            return Some(b.to_string());
        }
        if b.contains('(') {
            return None; // adrp 折叠式地址：不是对象基址
        }
        Some(b.to_string())
    };
    let top: Vec<String> = {
        let mut out = Vec::new();
        let mut depth = 0i32;
        let mut start = 0usize;
        for (i, c) in inner.char_indices() {
            match c {
                '(' | '[' => depth += 1,
                ')' | ']' => depth -= 1,
                ',' if depth == 0 => {
                    out.push(inner[start..i].to_string());
                    start = i + 1;
                }
                _ => {}
            }
        }
        out.push(inner[start..].to_string());
        out.into_iter()
            .map(|p| p.trim().trim_start_matches('#').trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()
    };
    match top.len() {
        // x64：基址与位移挤在一个操作数里（`rdi + 0x17` / `(mem(FP - 8)) + 7`）
        1 => {
            let (a, b) = split_plus(&top[0])?;
            Some((norm(&a)?, b.trim().to_string()))
        }
        // arm64：两个逗号分隔的操作数
        2 => Some((norm(&top[0])?, top[1].clone())),
        _ => None,
    }
}

/// 一次内存访问的分类：字段形 / 明确不是字段 / 形状看不懂。
/// 「看不懂」也要单独一类——访问器体里出现看不懂的对象基址访问时必须放弃，
/// 否则「唯一一处字段访问」可能只是「唯一一处**看得懂**的」。
#[derive(PartialEq, Clone, Copy)]
enum Acc {
    Field(u64),
    NotField,
    Unknown,
}

/// 分类一条内存操作数：`[base, #disp]` 且 base 是对象寄存器（非 PP/THR/SP/FP/…）。
/// `Field(off)` 里的 off 是字节偏移：机器码位移 = 字节偏移 − 1（tagged 折算）。
/// 未对齐的位移一律 Unknown——unboxed 字段（double/int64）**不带** tagged 折算，
/// 拿它当 tagged 字段会错位一格，必须挡掉。
fn classify_access(rl: &Roles, ctx: &FieldCtx, operand: &str) -> Acc {
    let m = mem_parts(operand);
    if m.stack {
        return Acc::NotField; // [FP/SP, …] 是栈槽
    }
    let inner = &m.parts.join(", ");
    let Some((base, disp)) = base_disp(inner) else {
        // 认不出形状：基址像对象时算「看不懂」，其余（池/线程/折叠地址）不是字段
        let raw_base = m.parts.first().map(|x| x.as_str()).unwrap_or("");
        let b = raw_base.split(&['+', ','][..]).next().unwrap_or("").trim();
        return if !b.is_empty() && !b.starts_with('(') && rl.obj_base(b) {
            Acc::Unknown
        } else {
            Acc::NotField
        };
    };
    if !rl.obj_base(&base) {
        return Acc::NotField; // PP/THR/SP/FP/NULL…：池、线程、栈
    }
    match parse_imm_i(&disp) {
        Some(d) if d < 1 => Acc::NotField, // 负/零位移：头部或局部，不是字段
        Some(d) => match ctx.offset_of(d) {
            Some(off) => Acc::Field(off),
            None => Acc::Unknown, // 未对齐：unboxed 字段或别的什么，不猜
        },
        None => Acc::Unknown, // 位移不是立即数
    }
}

/// 一条 IR 里所有内存访问的分类
fn op_accesses(rl: &Roles, ctx: &FieldCtx, op: &Op) -> Vec<Acc> {
    match op {
        Op::Assign { src: Expr::Mem(m), .. } => vec![classify_access(rl, ctx, m)],
        Op::Store { target, .. } => vec![classify_access(rl, ctx, target)],
        Op::PairLoad { .. } => vec![Acc::NotField],
        Op::Call { callee, .. } => {
            // 间接调用可能走字段（`call qword ptr [rbx+0x18]`）：算「看不懂」更稳
            if callee.contains('[') {
                vec![Acc::Unknown]
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

/// 访问器名推断：`get:X` / `set:X` 的函数体里**恰好一处**字段形访问 → (类, 偏移) → X。
/// 同一 (类, 偏移) 被两个不同名字claim 时不写（母类遮蔽时宁可没有）。
fn accessor_fields(
    cs: &Capstone,
    analyzer: &Analyzer,
    rl: &Roles,
    ctx: &FieldCtx,
) -> BTreeMap<(String, u64), String> {
    let names: BTreeMap<u64, String> = BTreeMap::new();
    let is_arm64 = analyzer.platform.arch == "arm64";
    let mut out: BTreeMap<(String, u64), String> = BTreeMap::new();
    let mut conflict: Vec<(String, u64)> = Vec::new();
    let mut seen_fn = 0usize;
    let (mut n_raw, mut n_eps, mut n_cls, mut n_two) = (0usize, 0usize, 0usize, 0usize);
    let dbg_on = std::env::var("DART_AOT_DEBUG_ACCESSOR").is_ok();
    for (&ref_, f) in analyzer.iso.functions.iter() {
        let Some((_ep, idx)) = analyzer.func_eps.get(&ref_).copied() else { continue };
        n_eps += 1;
        // 判据用**函数 kind**（3/6 = getter，4/7 = setter），不用名字前缀：
        // 私有字段的访问器带 `get:`/`set:` 前缀，公开字段的访问器就叫字段名本身。
        // kind 8（method extractor）名字也是方法名，排除。
        let vk = f.kind_tag & 0x1F;
        if !matches!(vk, 6 | 7) {
            continue;
        }
        let raw = analyzer.sref_str(f.name_ref).unwrap_or("");
        let fname = match raw.strip_prefix("get:").or_else(|| raw.strip_prefix("set:")) {
            Some(rest) => scrub_name(Some(rest)),
            None => scrub_name(Some(raw)),
        };
        // 操作符/合成名（`[]=`、`runtimeType`、`_set*`）不是字段名
        if fname.is_empty()
            || !fname.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            || !fname.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '=')
            || fname.starts_with("_set")
            || fname == "runtimeType"
            || fname.ends_with('=')
        {
            continue;
        }
        n_raw += 1;
        let Some(cls) = analyzer.class_of(f.owner_ref) else { continue };
        let class = scrub_name(analyzer.sref_str(cls.name_ref));
        if class.is_empty() {
            continue;
        }
        n_cls += 1;
        let Some((entry, csize)) = analyzer.code_range(idx) else { continue };
        let foff = entry + analyzer.slice_off;
        let end = (foff as usize + csize as usize + 16).min(analyzer.data.len());
        if foff as usize >= end {
            continue;
        }
        let (stmts, _) = lift(cs, rl, &analyzer.data[foff as usize..end], entry, is_arm64, &names);
        let limit = entry + csize;
        let mut offs: BTreeSet<u64> = BTreeSet::new();
        let mut unknown = 0usize;
        for st in stmts.iter().filter(|s| s.addr < limit) {
            for a in op_accesses(rl, ctx, &st.op) {
                match a {
                    Acc::Field(off) => {
                        offs.insert(off);
                    }
                    Acc::Unknown => unknown += 1,
                    Acc::NotField => {}
                }
            }
        }
        // 恰好一处字段访问、且没有看不懂的访问：getter 的返回值 / setter 的落点
        // 都只能是它，无需猜
        if offs.len() != 1 || unknown != 0 {
            n_two += 1;
            continue;
        }
        seen_fn += 1;
        if dbg_on {
            eprintln!("[dbg-accessor] {class}.{fname} @ off={:#x}", *offs.iter().next().unwrap());
        }
        let off = *offs.iter().next().unwrap();
        match out.get(&(class.clone(), off)) {
            Some(prev) if prev != &fname => {
                if std::env::var("DART_AOT_DEBUG_FIELDS").is_ok() {
                    eprintln!("[dbg-accessor] 同名冲突 {class} off={off:#x}: {prev} vs {fname}");
                }
                conflict.push((class, off))
            }
            Some(_) => {}
            None => {
                out.insert((class, off), fname);
            }
        }
    }
    for k in conflict {
        out.remove(&k);
    }
    if std::env::var("DART_AOT_DEBUG_FIELDS").is_ok() {
        eprintln!(
            "[dbg-accessor] 采信 {} 条；raw={n_raw} eps={n_eps} cls={n_cls} 唯一={seen_fn} 多访问={n_two}",
            out.len()
        );
    }
    out
}

/// 单个函数的字段注解上下文（类名 + 全局字段表 + 寄存器角色）
struct FieldAnnot<'a> {
    class: &'a str,
    ctx: &'a FieldCtx,
    rl: &'a Roles,
}

/// 基址是否可能是「对象」：寄存器，或溢出到栈上的接收者/参数
/// （`local_0`，x64 上常写成先 `rax = mem(FP - 8)` 再 `mem(rax + off)`——那一步
/// 也会被下面的 `mem(<栈槽>)` 分支接住）。
///
/// **排除**：框架寄存器（PP/THR/SP/FP/BARRIER/NULL…）、池式折叠地址（adrp 那类带括号
/// 加数的）、以及「从别的对象字段里取出来的对象」（`mem(x0, 0x10)` 当基址）——那种
/// 基址的类完全未知，与其猜不如不注解，内层访问本身仍会被单独注解。
fn field_base_ok(rl: &Roles, base: &str) -> bool {
    let mut b = base.trim();
    while let Some(inner) = b.strip_prefix('(').and_then(|x| x.strip_suffix(')')) {
        b = inner.trim();
    }
    if b.is_empty() {
        return false;
    }
    // `mem(<栈槽>)`：栈上的引用值（接收者/参数溢出）——只认栈槽，不认对象字段。
    // 两种写法都要认：arm64 `[FP, #-8]`（基址是独立操作数）、x64 `[FP - 8]`（同一操作数）。
    if let Some(inner) = b.strip_prefix("mem(").and_then(|x| x.strip_suffix(')')) {
        if mem_parts(inner).stack {
            return true;
        }
        let bt = inner.trim().split(['+', '-']).next().unwrap_or("").trim();
        return matches!(bt, "FP" | "SP");
    }
    if b.contains('(') || b.contains('+') || b.contains(',') {
        return false;
    }
    rl.obj_base(b)
}

/// 扫描一段文本里的 `mem(...)`（含嵌套），把能对上字段表的收集成注解。
fn field_notes(text: &str, ctx: &FieldCtx, class: &str, rl: &Roles, out: &mut Vec<String>) {
    let b: Vec<char> = text.chars().collect();
    let mut i = 0usize;
    while i + 4 <= b.len() {
        if b[i] == 'm' && b[i + 1] == 'e' && b[i + 2] == 'm' && b[i + 3] == '(' {
            let mut depth = 1i32;
            let mut j = i + 4;
            while j < b.len() {
                match b[j] {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            let inner: String = b[i + 4..j.min(b.len())].iter().collect();
            // 嵌套的先看（`mem(mem(x0, 0x10), 0x17)` 两个都是候选）
            field_notes(&inner, ctx, class, rl, out);
            if std::env::var("DART_AOT_DEBUG_NOTE").is_ok() {
                eprintln!("[dbg-note] class={class} inner={inner:?} parsed={:?} base_ok={:?}",
                    base_disp(&inner), base_disp(&inner).map(|(b,_)| field_base_ok(rl, &b)));
            }
            if let Some((base, disp)) = base_disp(&inner) {
                if field_base_ok(rl, &base) {
                    if let Some(d) = parse_imm_i(&disp) {
                        if let Some(off) = ctx.offset_of(d) {
                            if let Some(nm) = ctx.name(class, off) {
                                let note = format!("/* {class}.{nm} (off {off:#x}) */");
                                if !out.contains(&note) {
                                    out.push(note);
                                }
                            }
                        }
                    }
                }
            }
            i = j + 1;
            continue;
        }
        i += 1;
    }
}

/// 在行尾地址注释**之前**插入字段注解：`x0 = mem(x1, 0x17); // 0x..`
/// → `x0 = mem(x1, 0x17); /* _FutureListener.result (off 0x18) */ // 0x..`
/// 注解是**类内**说法：说的是「owner 类在这个偏移上的字段是 X」，没有声称基址就是
/// 该类的实例——所以基址只做「像不像对象」的排除，不做断言。
fn annotate_line(line: &str, fa: &FieldAnnot) -> String {
    // 先做一次子串预筛：绝大多数行没有内存访问，没必要为它们建 Vec<char>
    if fa.class.is_empty() || !line.contains("mem(") {
        return line.to_string();
    }
    if std::env::var("DART_AOT_NO_FIELD_NOTES").is_ok() {
        return line.to_string(); // A/B 计量用：关掉注解
    }
    let mut notes: Vec<String> = Vec::new();
    field_notes(line, fa.ctx, fa.class, fa.rl, &mut notes);
    if notes.is_empty() {
        return line.to_string();
    }
    let note = notes.join(" ");
    match line.rfind(" // ") {
        Some(p) => format!("{} {note} {}", &line[..p], &line[p..]),
        None => format!("{line} {note}"),
    }
}

// ---------------------------------------------------------------- 控制流结构化
//
// 目标：把「块 + goto」变成 if/else 与循环。做法是教科书式的两件套：
// 支配树找自然循环（回边：头支配尾），再按区域递归发射——两个分支汇合于同一结点
// 就是菱形（if/else），汇合不了就退回 `goto`（Dart 没有 goto，所以退回即标记为
// 未结构化，产物按伪代码对待，不假装是合法 Dart）。

#[derive(Debug, Clone)]
enum Node {
    Line(String),
    If { cond: String, then: Vec<Node>, els: Vec<Node> },
    While { cond: Option<String>, body: Vec<Node> },
    Break,
    Continue,
    Goto(u64),
}

struct Structurer<'a> {
    blocks: &'a [Block],
    /// **借用**而非持有：`Roles` 里有整张对象池映射（`pool: BTreeMap<u64, String>`，
    /// Reqable.app 有 122 064 条），而 Structurer 是每函数新建一个的——按值持有意味着
    /// 每个函数都深拷贝一遍池表。
    rl: &'a Roles,
    idx: BTreeMap<u64, usize>,
    loops: BTreeMap<usize, (usize, usize)>, // header idx → (body 入口, 出口)
    in_loop: BTreeMap<usize, usize>,    // block idx → 所属循环头 idx
    done: BTreeSet<usize>,
    /// 发射期当前所在的循环头栈：静态 in_loop 只说明"这个块属于某个循环"，
    /// 但该循环体可能已经在别处发完了；此时再发 `continue` 就跑到循环外面去了
    /// （实测一个 10k 函数应用里有 1 例，dart analyze 报 continue_outside_of_loop）。
    loop_stack: Vec<usize>,
    /// 尾复制已发射的语句数（每函数有上限，避免产物爆炸）
    dup_lines: usize,
    unstructured: bool,
    /// 未结构化的**首个**原因（诊断用；一旦置位不再改写，便于归因统计）
    reason: String,
}

impl Structurer<'_> {
    /// 标记未结构化并记下首个原因
    fn bail(&mut self, reason: &'static str) {
        self.unstructured = true;
        if self.reason.is_empty() {
            self.reason = reason.to_string();
        }
    }
}

/// Cooper–Harvey–Kennedy **立即支配者**算法，返回 `idom`（`usize::MAX` = 不可达/未定）。
///
/// 旧实现给每个块存一整份支配集（`Vec<BTreeSet<usize>>`，初值 `vec![(0..n).collect(); n]`），
/// 那是 **O(n²) 内存**：实测有 1608 块的函数，即 258 万个集合节点、上百 MB；而且每轮迭代都
/// 重新扫描全部块重建前驱表（CFG 在迭代中根本不变），配合 BTreeSet 的 clone+intersect，
/// 整体接近 O(n³)。而唯一的调用点只问一件事——「h 是否支配 u」（用来认回边/自然循环），
/// 所以换成 O(n) 的 idom 数组 + 沿支配树上溯。
///
/// 语义与旧实现逐点对齐：入口 `dom[0] == {0}` ↔ `idom[0] = 0`（上溯立即停）；
/// 不可达块旧实现给 `dom[b] = {b}`（无前驱 → 空集 ∪ {b}）↔ 这里保持 `idom[b] = MAX`，
/// `dominates` 先比自身再停，同样只在 `h == b` 时为真。
fn dominators(blocks: &[Block], idx: &BTreeMap<u64, usize>) -> Vec<usize> {
    let n = blocks.len();
    let mut idom: Vec<usize> = vec![usize::MAX; n];
    if n == 0 {
        return idom;
    }

    // 前驱表只建一次；与旧实现一致地排除自环（`p != b`）
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (p, blk) in blocks.iter().enumerate() {
        for (_, t) in &blk.succs {
            if let Some(&b) = idx.get(t) {
                if b != p {
                    preds[b].push(p);
                }
            }
        }
    }

    // 逆后序：从入口做迭代式 DFS（不用递归，函数 CFG 可能上千块深）
    let mut post: Vec<usize> = Vec::with_capacity(n);
    let mut visited = vec![false; n];
    let mut stack: Vec<(usize, usize)> = vec![(0, 0)];
    visited[0] = true;
    while let Some(top) = stack.last_mut() {
        let (b, i) = *top;
        match blocks[b].succs.get(i) {
            Some((_, t)) => {
                stack.last_mut().unwrap().1 += 1;
                if let Some(&nb) = idx.get(t) {
                    if !visited[nb] {
                        visited[nb] = true;
                        stack.push((nb, 0));
                    }
                }
            }
            None => {
                stack.pop();
                post.push(b);
            }
        }
    }
    post.reverse(); // 后序 → 逆后序
    let mut rpo = vec![usize::MAX; n];
    for (k, &b) in post.iter().enumerate() {
        rpo[b] = k;
    }

    idom[0] = 0;
    let mut changed = true;
    while changed {
        changed = false;
        for &b in &post {
            if b == 0 {
                continue;
            }
            let mut new_idom = usize::MAX;
            for &p in &preds[b] {
                if idom[p] == usize::MAX {
                    continue; // 本轮尚未确定的前驱跳过（CHK 的标准做法）
                }
                new_idom = if new_idom == usize::MAX {
                    p
                } else {
                    intersect_dom(p, new_idom, &idom, &rpo)
                };
            }
            if new_idom != usize::MAX && idom[b] != new_idom {
                idom[b] = new_idom;
                changed = true;
            }
        }
    }
    idom
}

/// CHK 的 intersect：沿支配树把较深的一方往上抬，直到相遇。
fn intersect_dom(mut b1: usize, mut b2: usize, idom: &[usize], rpo: &[usize]) -> usize {
    while b1 != b2 {
        while rpo[b1] > rpo[b2] {
            b1 = idom[b1];
        }
        while rpo[b2] > rpo[b1] {
            b2 = idom[b2];
        }
    }
    b1
}

/// 「h 是否支配 u」——沿 idom 上溯。不可达块只匹配自身（对齐旧的 `dom[u] = {u}`）。
fn dominates(idom: &[usize], h: usize, mut u: usize) -> bool {
    loop {
        if u == h {
            return true;
        }
        let next = idom[u];
        if next == usize::MAX || next == u {
            return false;
        }
        u = next;
    }
}

impl<'a> Structurer<'a> {
    fn new(blocks: &'a [Block], rl: &'a Roles) -> Self {
        let idx: BTreeMap<u64, usize> =
            blocks.iter().enumerate().map(|(i, b)| (b.start, i)).collect();
        let dom = dominators(blocks, &idx);
        let mut loops = BTreeMap::new();
        let mut in_loop = BTreeMap::new();
        // 回边 u → h（h 支配 u）⇒ 自然循环体 = {h} ∪ 能不经 h 到达 u 的块
        for (u, blk) in blocks.iter().enumerate() {
            for (_, t) in &blk.succs {
                let Some(&h) = idx.get(t) else { continue };
                if !dominates(&dom, h, u) {
                    continue;
                }
                let mut body: BTreeSet<usize> = BTreeSet::new();
                body.insert(h);
                let mut stack = vec![u];
                while let Some(x) = stack.pop() {
                    if !body.insert(x) {
                        continue;
                    }
                    for (p, pb) in blocks.iter().enumerate() {
                        if pb.succs.iter().any(|(_, t)| idx.get(t) == Some(&x)) && p != x {
                            stack.push(p);
                        }
                    }
                }
                // 出口：循环体内指向体外的边
                let mut exit = h;
                for &b in &body {
                    for (_, t) in &blocks[b].succs {
                        if let Some(&ti) = idx.get(t) {
                            if !body.contains(&ti) {
                                exit = ti;
                            }
                        }
                    }
                }
                loops.entry(h).or_insert((h, exit));
                for &b in &body {
                    in_loop.entry(b).or_insert(h);
                }
            }
        }
        Structurer {
            blocks,
            rl,
            idx,
            loops,
            in_loop,
            done: BTreeSet::new(),
            loop_stack: Vec::new(),
            dup_lines: 0,
            unstructured: false,
            reason: String::new(),
        }
    }

    /// 一条边的目标块下标
    fn succ(&self, b: usize, k: usize) -> Option<usize> {
        self.blocks[b].succs.get(k).and_then(|(_, t)| self.idx.get(t).copied())
    }

    fn term(&self, b: usize) -> Option<Op> {
        self.blocks[b].stmts.last().map(|s| s.op.clone())
    }

    /// 语句渲染（不含最后一条终结指令；先做块内表达式嵌套）
    fn body_lines(&self, b: usize) -> Vec<Node> {
        let mut v = Vec::new();
        let blk = &self.blocks[b];
        let n = blk.stmts.len();
        let cut = matches!(
            self.term(b),
            Some(Op::Branch { .. })
                | Some(Op::Return { .. })
                | Some(Op::Abort(_))
                | Some(Op::IndirectJump(_))
        ) as usize;
        let nested = nest_block(&blk.stmts[..n.saturating_sub(cut)], self.rl);
        for s in &nested {
            // 帧簿记走注释（与 stp/ldp 同口径）：Dart 里没有 FP/SP，写成赋值只会
            // 制造「写了没人读」的噪声
            if let Some(note) = Self::frame_note(s, self.rl) {
                v.push(Node::Line(note));
                continue;
            }
            if let Some(line) = render_op(self.rl, &s.op, s.addr) {
                v.push(Node::Line(line));
            }
        }
        v
    }

    /// 尾复制：目标块**已经发射过**（前向跳转 = 共享尾块），把那段直线代码再写一遍。
    ///
    /// 为什么不是 goto：Dart 没有 goto（产物只能写 `gotoLabel(...)` 占位），而共享尾块在
    /// 真实 Dart 代码里对应的就是重复的代码；IDA/LLVM 对这种情况同样做尾复制。
    /// 纪律：只复制**单后继的直线段**，必须在终止符（return/abort）收尾；段长与每函数
    /// 总复制量都有上限；回头跳（循环）不复制。复制出来的语句前会打一行注释说明来源。
    fn dup_tail(&mut self, start: usize, budget_blocks: usize) -> Option<Vec<Node>> {
        let mut out: Vec<Node> = Vec::new();
        let mut seen: BTreeSet<usize> = BTreeSet::new();
        let mut b = start;
        let mut lines = 0usize;
        for _ in 0..budget_blocks {
            if !seen.insert(b) {
                return None; // 自环
            }
            lines += self.body_lines(b).len();
            if self.dup_lines + lines > 256 {
                return None;
            }
            out.extend(self.body_lines(b));
            match self.term(b) {
                Some(Op::Return { value }) => {
                    out.push(Node::Line(self.ret_line(b, &value)));
                    self.dup_lines += lines;
                    return Some(out);
                }
                Some(Op::Abort(n)) => {
                    out.push(Node::Line(format!("abort(); // brk #{n:#x}")));
                    self.dup_lines += lines;
                    return Some(out);
                }
                // 有条件分支：复制它就得连两支一起复制，超出"共享尾块"的范围了
                Some(Op::Branch { cond: Some(_), .. }) => return None,
                Some(Op::Branch { cond: None, target }) => match self.idx.get(&target) {
                    Some(&t) if t != b => b = t,
                    _ => return None,
                },
                _ => match self.succ(b, 0) {
                    Some(n) if n != b => b = n,
                    _ => {
                        self.dup_lines += lines;
                        return Some(out);
                    }
                },
            }
        }
        None
    }

    /// `ret` 的渲染：`Return { value: None }` 在机器层是「x0/rax 里是返回值」。
    /// 若本块最后一条语句正是写返回寄存器，就写成 `return x0;`——比裸 `return;` 忠实，
    /// 也消掉一大类 `unused_local_variable`（实测一个自编程序里 3,290 条警告，多数是
    /// 「写了返回值寄存器却没人读」的形态）。
    fn ret_line(&self, b: usize, value: &Option<String>) -> String {
        if let Some(v) = value {
            return format!("return {v};");
        }
        const RET_REGS: [&str; 3] = ["x0", "rax", "eax"];
        let last_assign = self.blocks[b]
            .stmts
            .iter()
            .rev()
            .find_map(|st| match &st.op {
                Op::Assign { dst, .. } => Some(dst.as_str()),
                _ => None,
            });
        match last_assign {
            Some(d) if RET_REGS.contains(&d) => format!("return {d};"),
            _ => "return;".to_string(),
        }
    }

    /// 帧簿记（`FP = SP` / `SP = SP ± n`）在 Dart 层不存在，与 `stp/ldp` 一样当注释保留。
    /// 这样 FP/SP 不再以「写了没人读」的赋值形态出现。
    fn frame_note(st: &Stmt, rl: &Roles) -> Option<String> {
        let Op::Assign { dst, src } = &st.op else { return None };
        let d = sanitize_regs(dst);
        let sx = src.text(rl);
        if d == "FP" && sx.trim_start_matches('(').starts_with("SP") {
            return Some(format!("// frame: {d} = {sx} // {:#x}", st.addr));
        }
        if d == "SP" {
            let rest = sx.trim_start_matches('(').trim_start_matches("SP").trim_start();
            if rest.starts_with('+') || rest.starts_with('-') {
                return Some(format!("// frame: {d} = {sx} // {:#x}", st.addr));
            }
        }
        None
    }

    /// 该分支是否「自身终止」（沿路只走单后继、最终遇到 return/brk/区域外跳转）。
    /// 用于 if-return 形状：`if (c) { return x; } <继续走另一支>`
    fn terminates(&self, mut b: usize) -> bool {
        for _ in 0..64 {
            match self.term(b) {
                Some(Op::Return { .. }) | Some(Op::Abort(_)) | Some(Op::IndirectJump(_)) => {
                    return true
                }
                Some(Op::Branch { cond: Some(_), .. }) => return false,
                Some(Op::Branch { cond: None, target }) => match self.idx.get(&target) {
                    Some(&t) if t != b => b = t,
                    _ => return true, // 跳到函数外/自环：视为不落在区域内
                },
                _ => match self.succ(b, 0) {
                    Some(n) if n != b => b = n,
                    _ => return true,
                },
            }
        }
        false
    }

    /// 两个分支的最近公共汇合点（BFS 交替推进，遇到同一结点即汇合）
    fn find_join(&self, a: usize, b: usize) -> Option<usize> {
        if a == b {
            return Some(a);
        }
        let mut seen_a: BTreeSet<usize> = BTreeSet::new();
        let mut seen_b: BTreeSet<usize> = BTreeSet::new();
        let mut qa = vec![a];
        let mut qb = vec![b];
        for _ in 0..512 {
            let mut na = Vec::new();
            for x in qa {
                if !seen_a.insert(x) {
                    continue;
                }
                if seen_b.contains(&x) {
                    return Some(x);
                }
                for k in 0..self.blocks[x].succs.len() {
                    if let Some(s) = self.succ(x, k) {
                        na.push(s);
                    }
                }
            }
            let mut nb = Vec::new();
            for x in qb {
                if !seen_b.insert(x) {
                    continue;
                }
                if seen_a.contains(&x) {
                    return Some(x);
                }
                for k in 0..self.blocks[x].succs.len() {
                    if let Some(s) = self.succ(x, k) {
                        nb.push(s);
                    }
                }
            }
            qa = na;
            qb = nb;
            if qa.is_empty() && qb.is_empty() {
                return None;
            }
        }
        None
    }

    /// 递归结构化 [start, stop)
    /// 递归结构化：`depth` 是**嵌套层数**，超过 `MAX_STRUCT_DEPTH` 就不再往里钻，
    /// 只把当前块的语句发出来并把跳转如实写成 gotoLabel。
    ///
    /// 为什么必须有这个上限：`seq` 每遇到一个菱形就往里递归一层，块多的时候能钻到
    /// **几十层**（实测 arm64 ELF 的 `h212keep_linux_arm64` 钻到约 50 层）——产物变成
    /// 一片阶梯状的 `}`，`dart analyze` 直接报 `stack_overflow`（嵌套过深）。
    /// 好代码本来也不会嵌那么深，所以这是"拒绝生成不可读产物"而不是能力损失。
    fn seq(&mut self, start: usize, stop: Option<usize>, depth: usize) -> Vec<Node> {
        let mut out: Vec<Node> = Vec::new();
        let mut cur = Some(start);
        let mut guard = 0usize;
        while let Some(b) = cur {
            guard += 1;
            if guard > 4096 || depth > MAX_STRUCT_DEPTH {
                if depth > MAX_STRUCT_DEPTH {
                    self.bail("depth-limit");
                    out.push(Node::Goto(self.blocks[b].start));
                }
                break;
            }
            if Some(b) == stop || !self.done.insert(b) {
                break;
            }
            // 循环头：条件在循环体内求值，故头块语句进 body
            if let Some(&(_, exit)) = self.loops.get(&b) {
                let (cond, body_entry) = self.loop_shape(b);
                let mut body = self.body_lines(b);
                // 头块那条指向「立即汇合侧块」的条件分支要在 body 顶部补发成守卫 `if`：
                // 下面的 `continue` 会跳过整个 Branch match，否则它凭空消失
                // （栈溢出 stub 于是从「仅 SP<=BARRIER 时调用」变成每圈无条件调用）。
                // stop 取 body_entry：侧块的形态是 `bl <stub>; b <落空块>`，遇到它就收尾。
                // 放在 `loop_stack.push(b)` **之前**——侧块在循环上下文之外。
                if let Some(Op::Branch { cond: Some(gc), target }) = self.term(b) {
                    if let (Some(ti), Some(fi)) =
                        (self.idx.get(&target).copied(), self.succ(b, 1))
                    {
                        if ti != body_entry && self.is_rejoin_side_block(ti, fi) {
                            let then = self.seq(ti, Some(body_entry), depth + 1);
                            body.push(Node::If {
                                cond: gc.clone(),
                                then,
                                els: vec![],
                            });
                        }
                    }
                }
                self.loop_stack.push(b);
                body.extend(self.seq(body_entry, Some(b), depth + 1));
                self.loop_stack.pop();
                out.push(Node::While { cond, body });
                cur = Some(exit);
                continue;
            }
            out.extend(self.body_lines(b));
            match self.term(b) {
                Some(Op::Return { value }) => {
                    out.push(Node::Line(self.ret_line(b, &value)));
                    break;
                }
                Some(Op::Abort(n)) => {
                    out.push(Node::Line(format!("abort(); // brk #{n:#x}")));
                    break;
                }
                Some(Op::IndirectJump(r)) => {
                    out.push(Node::Line(format!("gotoIndirect({r});")));
                    break;
                }
                Some(Op::Branch { cond: Some(c), target }) => {
                    let t = self.idx.get(&target).copied();
                    let f = self.succ(b, 1);
                    // 循环内：出口边 → break；回边 → continue
                    let in_l = self.in_loop.get(&b).copied().filter(|h| self.loop_stack.contains(h));
                    if let Some(h) = in_l {
                        let t_out = t.map(|x| self.in_loop.get(&x).copied() != Some(h)).unwrap_or(true);
                        if t_out {
                            out.push(Node::If {
                                cond: c.clone(),
                                then: vec![Node::Break],
                                els: vec![],
                            });
                            cur = f;
                            continue;
                        }
                        if self.loops.contains_key(&h) && t == Some(h) {
                            out.push(Node::If {
                                cond: c.clone(),
                                then: vec![Node::Continue],
                                els: vec![],
                            });
                            cur = f;
                            continue;
                        }
                    }
                    // 条件分支落在**最后一个块**时没有落空后继（`f` 为 None）：
                    // 真实原因是函数字节范围在分支处就结束了（表给的尺寸截断），
                    // 不是"目标越界"。此时把目标支结构成 `if (...) { ... }` 并收尾——
                    // 以前这里一律 bail，白白让 713 个分支退化成不可结构化
                    // （arm64 ELF 语料实测：结构化率因此从 ~88% 掉到 34%）。
                    if f.is_none() {
                        if let Some(ti) = t {
                            let then = self.seq(ti, stop, depth + 1);
                            out.push(Node::If {
                                cond: c.clone(),
                                then,
                                els: vec![],
                            });
                            break;
                        }
                    }
                    match (t, f) {
                        (Some(ti), Some(fi)) => {
                            // 汇合点 == 区域终点也算合法菱形：两支各自走到区域末尾，
                            // 只是不再有「汇合之后」的语句（历史实现把它排除掉，
                            // 白白让 1/4 的 if/else 退回 goto）。
                            if let Some(j) = self.find_join(ti, fi) {
                                let then = self.seq(ti, Some(j), depth + 1);
                                let els = self.seq(fi, Some(j), depth + 1);
                                out.push(Node::If {
                                    cond: c.clone(),
                                    then,
                                    els,
                                });
                                if Some(j) == stop {
                                    break;
                                }
                                cur = Some(j);
                            } else if self.terminates(ti) {
                                // if-return 形状：true 支自身终止（return/brk/跳出区域），
                                // 另一支继续——直接发射 `if (c) { 支 }` 并顺着 else 支走。
                                let then = self.seq(ti, stop, depth + 1);
                                out.push(Node::If {
                                    cond: c.clone(),
                                    then,
                                    els: vec![],
                                });
                                cur = Some(fi);
                            } else if self.terminates(fi) {
                                // 镜像形状：else 支终止 → 取反后作为 then 发射
                                let els = self.seq(fi, stop, depth + 1);
                                out.push(Node::If {
                                    cond: negate_cond(&c),
                                    then: els,
                                    els: vec![],
                                });
                                cur = Some(ti);
                            } else {
                                // 真正不可归约：只保留 true 支，其余如实退回 goto
                                self.bail("no-join:irreducible");
                                out.push(Node::If {
                                    cond: c.clone(),
                                    then: self.seq(ti, stop, depth + 1),
                                    els: vec![],
                                });
                                out.push(Node::Goto(self.blocks[fi].start));
                                break;
                            }
                        }
                        _ => {
                            if self.reason.is_empty() {
                                self.reason = format!(
                                    "target-out-of-function blk={:#x} target={target:#x} lo={:#x} hi={:#x} delta={}",
                                    self.blocks[b].start,
                                    self.blocks[0].start,
                                    self.blocks.last().map(|x| x.start).unwrap_or(0),
                                    target as i64 - self.blocks[0].start as i64
                                );
                            }
                            self.unstructured = true;
                            out.push(Node::Line(format!("if ({c}) {{ /* target outside this function */ }}")));
                            break;
                        }
                    }
                }
                Some(Op::Branch { cond: None, target }) => {
                    let t = self.idx.get(&target).copied();
                    if t == stop {
                        break;
                    }
                    if let Some(h) = self
                        .in_loop
                        .get(&b)
                        .copied()
                        .filter(|h| self.loop_stack.contains(h))
                    {
                        if self.loops.contains_key(&h) && t == Some(h) {
                            out.push(Node::Continue);
                            break;
                        }
                    }
                    // 目标块没访问过就顺着走；已访问过（共享尾块/非头回边）或目标不在本函数
                    // 块表里（越界跳转）就如实 goto——绝不索引不存在的块（曾因此 panic）
                    match t {
                        Some(ti) if !self.done.contains(&ti) => {
                            cur = Some(ti);
                        }
                        Some(ti) => {
                            let forward = self.blocks[ti].start > self.blocks[b].start;
                            if forward {
                                if let Some(tail) = self.dup_tail(ti, 16) {
                                    out.push(Node::Line(format!(
                                        "// duplicated tail (join at {:#x}; the same code was \
                                         emitted above)",
                                        self.blocks[ti].start
                                    )));
                                    out.extend(tail);
                                    break;
                                }
                            }
                            self.bail("branch-to-done-block");
                            out.push(Node::Goto(target));
                            break;
                        }
                        None => {
                            self.bail("branch-outside-function");
                            out.push(Node::Goto(target));
                            break;
                        }
                    }
                }
                _ => {
                    cur = self.succ(b, 0);
                }
            }
        }
        out
    }

    /// 循环形状：条件来自头块的终结分支（true 支在体内 ⇒ while(cond)；否则 while(true)）
    /// `t` 是否是一个**立即重新汇合**到 `rejoin` 的侧块：它的终止符是一条无条件跳转、
    /// 且目标正好是 `rejoin`。
    ///
    /// 这是识别「循环头的守卫」的局部判据，**不依赖循环归属**——上一版用
    /// `in_loop[target] != Some(h)` 判别失败了，因为 Dart 的 out-of-line 栈溢出处理块
    /// 形态是 `bl <stub>; b <落空块>`，它**跳回循环内**，于是被循环检测标成 in_loop，
    /// 判据恒假。改成看形状之后就不受归属影响了。
    fn is_rejoin_side_block(&self, t: usize, rejoin: usize) -> bool {
        matches!(
            self.term(t),
            Some(Op::Branch { cond: None, target })
                if self.idx.get(&target).copied() == Some(rejoin)
        )
    }

    fn loop_shape(&self, h: usize) -> (Option<String>, usize) {
        match self.term(h) {
            Some(Op::Branch { cond: Some(c), target }) => {
                let ti = self.idx.get(&target).copied();
                let fi = self.succ(h, 1);
                let inside = ti.filter(|t| self.in_loop.get(t) == Some(&h));
                let outside = fi.filter(|t| self.in_loop.get(t) != Some(&h));
                match (inside, outside) {
                    (Some(inn), Some(_)) => (Some(c), inn),
                    _ => {
                        // 头块的条件分支若指向一个**立即汇合回落空块**的侧块，那它不是循环条件
                        // 而是守卫（Dart 的循环头就是栈溢出检查：`ldr BARRIER,[THR,#lim];
                        // cmp SP,BARRIER; b.ls <handler>`，而 handler 是 `bl <stub>; b <落空块>`）。
                        // 此时循环体必须从**落空边**进入；原来一律用 `succ(h,0)`＝分支目标，
                        // 于是 handler 被当成循环体入口，产物里 `ldr` 后面直接接上 `bl <stub>`
                        // （两条语句地址相差 0x64），守卫的 `if` 随循环头路径的 `continue` 消失。
                        let entry = match (ti, fi) {
                            (Some(t), Some(f)) if self.is_rejoin_side_block(t, f) => f,
                            _ => self.succ(h, 0).unwrap_or(h),
                        };
                        (None, entry)
                    }
                }
            }
            _ => (None, self.succ(h, 0).unwrap_or(h)),
        }
    }
}

fn render_nodes(
    nodes: &[Node],
    indent: usize,
    out: &mut String,
    unstructured: &mut bool,
    fa: &FieldAnnot,
) {
    let pad = "  ".repeat(indent + 1);
    for n in nodes {
        match n {
            Node::Line(l) => {
                // Node::Line 也绕过 render_op（结构化器的兜底分支直接拼了字符串），
                // 所以这里再兜一次；对已清洗过的文本是幂等的。
                let l = annotate_line(&sanitize_regs(&sanitize_mem_refs(l)), fa);
                let _ = writeln!(out, "{pad}{l}");
            }
            Node::If { cond, then, els } => {
                // 条件文本绕过 render_op（不经过那边的 sanitize），单独过一遍：
                // x86 的 `qword ptr [THR + 0x40]` 直接进 `if (...)` 就是语法错误
                let cond = annotate_line(&sanitize_regs(&sanitize_mem_refs(cond)), fa);
                let _ = writeln!(out, "{pad}if ({cond}) {{");
                render_nodes(then, indent + 1, out, unstructured, fa);
                if els.is_empty() {
                    let _ = writeln!(out, "{pad}}}");
                } else {
                    let _ = writeln!(out, "{pad}}} else {{");
                    render_nodes(els, indent + 1, out, unstructured, fa);
                    let _ = writeln!(out, "{pad}}}");
                }
            }
            Node::While { cond, body: _ } => match cond {
                Some(c) => {
                    let c = annotate_line(&sanitize_regs(&sanitize_mem_refs(c)), fa);
                    let _ = writeln!(out, "{pad}while ({c}) {{");
                }
                None => {
                    let _ = writeln!(out, "{pad}while (true) {{");
                }
            },
            Node::Break => {
                let _ = writeln!(out, "{pad}break;");
            }
            Node::Continue => {
                let _ = writeln!(out, "{pad}continue;");
            }
            Node::Goto(a) => {
                *unstructured = true;
                // Dart 没有 goto（`goto L40a8;` 连解析都过不去）：写成占位调用，
                // 明确「控制权转去 0x40a8」，函数头的 NOTE 也仍然标着伪代码。
                let _ = writeln!(out, "{pad}gotoLabel(0x{a:x});");
            }
        }
        if let Node::While { body, .. } = n {
            render_nodes(body, indent + 1, out, unstructured, fa);
            let _ = writeln!(out, "{pad}}}");
        }
    }
}

/// x86 的内存写法 → Dart：`qword ptr [THR + 0x40]` → `mem(THR + 0x40)`。
/// 产物里不该出现任何 `[`（Dart 的 `[` 只在列表/索引处合法），所以这里把每个
/// 方括号段整体换成 `mem(...)`，并吃掉 `byte/word/dword/qword ptr` 尺寸前缀。
fn sanitize_mem_refs(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let b: Vec<char> = text.chars().collect();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == '[' {
            let mut depth = 1i32;
            let mut j = i + 1;
            while j < b.len() && depth > 0 {
                match b[j] {
                    '[' => depth += 1,
                    ']' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            let inner: String = b[i + 1..j.saturating_sub(1)].iter().collect();
            out.push_str(&format!("mem({})", inner.trim()));
            i = j;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    // 尺寸前缀去掉（它是 x86 语法，Dart 里是未定义标识符）。
    // **长的先替**：`word ptr ` 是 `qword ptr ` 的子串，短名先替会把 `qword ptr [..]`
    // 削成 `qmem(...)`（实测 2.13/2.14/3.3 三个版本的产物里各有上百条）。
    let mut t = out;
    // 段前缀（`ds:`/`fs:`）同样是 x86 语法
    for seg in ["cs:", "ds:", "es:", "fs:", "gs:", "ss:"] {
        while t.contains(seg) {
            t = t.replace(seg, "");
        }
    }
    for pre in ["qword ptr ", "dword ptr ", "xword ptr ", "byte ptr ", "word ptr ", "ptr "] {
        while t.contains(pre) {
            t = t.replace(pre, "");
        }
    }
    t
}

/// `needle` 是否作为**完整的词**出现在 `haystack` 里（两侧都不是标识符字节）。
///
/// 寄存器名判定一律要用它，不能用 `contains`：`x27` 是 `0x27` 的子串、`x1` 是 `x17`
/// 的子串，裸子串匹配会把位移文本和更长的寄存器名误判成短名（`ppmem` 那个 bug
/// 就是这么来的，见池加载分支的注释）。与 `replace_word` 同一套边界定义。
fn contains_word(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let b = haystack.as_bytes();
    let nb = needle.as_bytes();
    let mut i = 0usize;
    while i + nb.len() <= b.len() {
        if b[i..].starts_with(nb)
            && (i == 0 || !is_word_byte(b[i - 1]))
            && (i + nb.len() >= b.len() || !is_word_byte(b[i + nb.len()]))
        {
            return true;
        }
        i += 1;
    }
    false
}

/// 寄存器名里的 `.` 会让 Dart 把它读成成员访问：`v2.2d = min(v9.2d, v5.2d);`
/// 会解析成 `v2 . 2d = ...`。arm64 的 SIMD 车道写法统一收敛成 `v2_2d`。
fn sanitize_regs(text: &str) -> String {
    let b: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < b.len() {
        // 命中 `v<数字>.<数字><字母>`（车道）才替换点号
        if (b[i] == 'v' || b[i] == 'q' || b[i] == 'd' || b[i] == 's')
            && b.get(i + 1).map(|c| c.is_ascii_digit()).unwrap_or(false)
        {
            let start = i;
            let mut j = i + 1;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if b.get(j) == Some(&'.')
                && b.get(j + 1).map(|c| c.is_ascii_digit()).unwrap_or(false)
            {
                let mut k = j + 1;
                while k < b.len() && b[k].is_ascii_digit() {
                    k += 1;
                }
                if b.get(k).map(|c| c.is_ascii_alphabetic()).unwrap_or(false) {
                    out.extend(b[start..j].iter());
                    out.push('_');
                    out.extend(b[j + 1..k + 1].iter());
                    i = k + 1;
                    continue;
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// 单条 IR → 伪代码行（None = 不产出，如无跳转意义的指令）
fn render_op(rl: &Roles, op: &Op, addr: u64) -> Option<String> {
    let line = render_op_inner(rl, op, addr)?;
    Some(sanitize_regs(&sanitize_mem_refs(&line)))
}

fn render_op_inner(rl: &Roles, op: &Op, addr: u64) -> Option<String> {
    match op {
        Op::Assign { dst, src } => Some(format!("{dst} = {}; // {addr:#x}", src.text(rl))),
        Op::Cmp => None,
        Op::IndirectJump(r) => Some(format!("gotoIndirect({r}); // {addr:#x}")),
        Op::Helper(t) => Some(format!("{t}; // {addr:#x}")),
        Op::PairLoad { base, disp, d1, d2 } => {
            Some(format!("memRead2({base}, {disp}, {d1}, {d2}); // {addr:#x}"))
        }
        Op::Note(t) => Some(format!("// {t} // {addr:#x}")),
        Op::Abort(n) => Some(format!("abort(); // brk #{n:#x} @ {addr:#x}")),
        Op::Call {
            dst,
            target,
            callee,
            resolved,
        } => {
            // `call foo` 不是 Dart（两个标识符连写）；渲染成真正的调用表达式 `foo()`。
            // 目标有名字写名字（可读性关键），没名字写 `sub_0x...`（合法标识符：不以数字开头）。
            let call = match target {
                Some(t) => match resolved {
                    Some(n) if n.as_str() == format!("sub_{t:#x}") => format!("{n}()"),
                    Some(n) => format!("{n}() /* 0x{t:x} */"),
                    None => format!("sub_{t:#x}()"),
                },
                None => format!("callIndirect({callee})"),
            };
            Some(match dst {
                Some(d) => format!("{d} = {call}; // {addr:#x}"),
                None => format!("{call}; // {addr:#x}"),
            })
        }
        Op::Store { target, value } => {
            Some(format!("{} // {addr:#x}", mem_write(target, value)))
        }
        Op::Branch { .. } | Op::Return { .. } => None,
        Op::Other(t) => Some(format!("// unmapped: {t} // {addr:#x}")),
    }
}

// ---------------------------------------------------------------- 表达式嵌套
//
// ddc 的寄存器值视图（Live/Pending）在 dae 这里的简化版：块内把「寄存器 ← 表达式」
// 折成待定值，读到它时**内联**；块尾统一落地成局部变量。这样 `rax = [THR+0x80]` 再
// `rax = [rax+0xa80]` 会折叠成一条可读表达式，而不是两行中间寄存器。
//
// 两条纪律：
// - 折叠有深度上限（默认 3），免得产出没法读的长表达式；
// - 调用是屏障：调用前先落地（调用可能改寄存器），折叠绝不跨越调用。

const NEST_MAX_DEPTH: usize = 3;

fn nest_block(stmts: &[Stmt], rl: &Roles) -> Vec<Stmt> {
    let mut out: Vec<Stmt> = Vec::new();
    let mut pending: BTreeMap<String, (String, usize, u64)> = BTreeMap::new();
    let flush = |pending: &mut BTreeMap<String, (String, usize, u64)>, out: &mut Vec<Stmt>, _addr: u64| {
        for (r, (e, _, a)) in std::mem::take(pending) {
            if e != r {
                out.push(Stmt {
                    addr: a,
                    op: Op::Assign {
                        dst: r,
                        src: Expr::Text(e),
                    },
                });
            }
        }
    };
    for st in stmts {
        match &st.op {
            Op::Note(_)
            | Op::Abort(_)
            | Op::Other(_)
            | Op::Cmp
            | Op::IndirectJump(_)
            | Op::Helper(_)
            | Op::PairLoad { .. } => {
                // **落地而不是丢弃**。这里原先是 `pending.clear()`，会把待定值静默扔掉——
                // 而这些指令里的 `push`/`pop`（归类成 `Op::Note` 的 `frame/align:`）恰恰是
                // 调用实参准备链的终点：x64 上 `mov rcx,rax; sub rcx,1; push rcx; call fib`
                // 折成待定值 `rcx = rax - 1` 后，一遇到 `push rcx` 就被清掉，于是产物里的
                // `fib()` 既看不到实参、也没有任何一行提到 `n - 1`，而且**不计入 unmapped**
                // （指令是认得的，只是结果被扔了），所以既有门禁全都看不见。
                // 实测 G_class_args_branch 的 `fib` 因此少 3 条语句（两次递归调用的实参准备）。
                //
                // 与 `Call`/`Store`/`Branch`/`Return` 分支保持一致（它们本来就是 flush）。
                // 对折叠质量没有损失：`Cmp` 原本也清空 pending，所以后续 `Branch` 的
                // `subst_regs` 本来就拿不到东西——这一改只是把「丢掉」换成「写出来」。
                flush(&mut pending, &mut out, st.addr);
                out.push(Stmt { addr: st.addr, op: st.op.clone() });
                continue;
            }
            Op::Assign { dst, src } => {
                let text = match src {
                    Expr::Reg(r) => pending
                        .get(r)
                        .map(|(e, _, _)| e.clone())
                        .unwrap_or_else(|| r.clone()),
                    Expr::Imm(v) => format!("{v}"),
                    Expr::Pool(i) => format!("pp[0x{i:x}]"),
                    Expr::Mem(m) => {
                        let d = pending.values().map(|(_, d, _)| *d).max().unwrap_or(0);
                        if d < NEST_MAX_DEPTH {
                            mem_read(rl, &subst_regs(m, &pending, rl))
                        } else {
                            // 折不动 ⇒ **先落地**。见下面 `Expr::Text` 分支的说明：
                            // 留在 pending 里的值会被后续同 dst 赋值覆盖而彻底消失。
                            flush(&mut pending, &mut out, st.addr);
                            mem_read(rl, m)
                        }
                    }
                    // `Expr::Text` 也必须替换待定值，否则**定义会被静默吞掉**：
                    // pending 按 dst 建键，`x2 = (condFlag("ne")) ? 1 : 0` 之后紧跟
                    // `x2 = (x2 << 1)` 时，`insert` 直接覆盖旧条目，而新文本里的 `x2`
                    // 又没被替换 ⇒ 前一条既不落地、也不参与折叠，产物里凭空少一行，
                    // 剩下的 `x2 = x2 << 1` 引用的是一个从未在本函数赋过值的 x2。
                    // 与 `Expr::Mem` 分支同构（同样受 NEST_MAX_DEPTH 限制）。
                    Expr::Text(x) => {
                        let d = pending.values().map(|(_, d, _)| *d).max().unwrap_or(0);
                        if d < NEST_MAX_DEPTH {
                            subst_regs(x, &pending, rl)
                        } else {
                            // 折不动 ⇒ **先落地**，不能就这么把旧值留在 pending 里。
                            //
                            // `NEST_MAX_DEPTH` 只是可读性约束（别产出一行读不完的长表达式），
                            // 但「跳过替换」的副作用是致命的：pending 按 dst 建键，后面任何
                            // 一条同 dst 的赋值都会 `insert` 覆盖掉它，于是那个值**既没折进
                            // 读者、也没单独落地**，凭空消失。
                            //
                            // 实测 sample_arm64 `BigIntImpl.get_hashCode`：
                            // `csetm r5,eq; and r5,r5,BARRIER; add r5,r5,r17; asr r4,r5,#1`
                            // 到 `asr` 那步深度已达 3、替换被跳过，紧接着
                            // `ldur r5,[r2,#0xf]` 覆盖 pending[r5]，于是产物只剩
                            // `x4 = x5 >> 1`——整条哈希计算（含那个三元式）全丢。
                            // 落地之后是两三条短语句，比一行 110 字符的嵌套更好读。
                            flush(&mut pending, &mut out, st.addr);
                            x.clone()
                        }
                    }
                };
                let depth = pending.get(dst).map(|(_, d, _)| *d).unwrap_or(0) + 1;
                pending.insert(dst.clone(), (text, depth, st.addr));
            }
            Op::Call { .. } | Op::Store { .. } => {
                // 调用会改寄存器、写内存会改内存：都先落地，折叠不跨越它们
                flush(&mut pending, &mut out, st.addr);
                out.push(st.clone());
            }
            Op::Branch { cond, .. } => {
                let c = cond.as_ref().map(|c| {
                    let d = pending.values().map(|(_, d, _)| *d).max().unwrap_or(0);
                    if d < NEST_MAX_DEPTH {
                        subst_regs(c, &pending, rl)
                    } else {
                        c.clone()
                    }
                });
                flush(&mut pending, &mut out, st.addr);
                out.push(Stmt {
                    addr: st.addr,
                    op: Op::Branch {
                        cond: c,
                        target: match &st.op {
                            Op::Branch { target, .. } => *target,
                            _ => 0,
                        },
                    },
                });
            }
            Op::Return { .. } => {
                flush(&mut pending, &mut out, st.addr);
                out.push(st.clone());
            }
        }
    }
    flush(&mut pending, &mut out, stmts.last().map(|s| s.addr).unwrap_or(0));
    out
}

/// 把操作数文本里的寄存器替换成待定表达式（词边界匹配，深度受 pending 自身限制）
fn subst_regs(text: &str, pending: &BTreeMap<String, (String, usize, u64)>, rl: &Roles) -> String {
    let mut s = text.to_string();
    let mut names: Vec<&String> = pending.keys().collect();
    names.sort_by_key(|n| std::cmp::Reverse(n.len()));
    for n in names {
        let (e, _, _) = &pending[n];
        if e == n {
            continue;
        }
        // 纯寄存器别名（如 FP = SP）不做替换：语义等价但可读性更差。
        //
        // ⚠️ 这里**刻意不放过单 token 的立即数**（`0x1cf2` / `-0xa0001`），尽管把它们
        // 折进去看着更清楚（`mov r17,#0x1cf2; movk r17,#0xd,lsl#16` 现在产出
        // `x17 = (x17 & 0xffff) | 0xd0000`，读的人得自己算常量）。原因是它会**打破
        // dart analyze**：伪码里寄存器与占位函数都是 `dynamic`，`dynamic - dynamic`
        // 的静态类型还是 `dynamic`（什么运算符都能用），而一旦一边换成 `int` 字面量，
        // `int - dynamic` 的静态类型变成 `num`——`num` 没有 `<<`/`&`/`|`，于是
        // `((64) - (clz(x0))) << 1` 报 undefined_operator。
        // 实测 sample_arm64 `Smi.get_bitLength` 与 T4_blank 各命中一处，
        // `emitted_dart_is_valid` 门禁直接红。要拿到这个可读性收益，得先给伪码
        // 前导声明一套自洽的类型（让占位函数返回 int 而不是 dynamic），是独立工程。
        if e.split(|c: char| !c.is_ascii_alphanumeric()).filter(|s| !s.is_empty()).count() == 1
            && !e.contains('[')
            && !e.contains('+')
        {
            continue;
        }
        // 池里的**字符串字面量**不能替换进算术表达式。寄存器持有的是池槽的**地址**，
        // 而字面量是「那个地址上存的内容」，两者不是同一个东西；替换进 `base + index*8 + disp`
        // 之后 Dart 会读成 `String + int` → `argument_type_not_assignable`（实测 2.18.1 语料
        // 命中）。字面量在它被载入的那一行照常显示（`rax = " fib(20)=" /* pp+0x1e08 */`），
        // 那才是它该出现的地方；后续引用保持寄存器名。不含算术的引用（如 `call(x0)`）仍替换。
        if e.starts_with('"') && s.contains(['+', '*', '-']) {
            continue;
        }
        // 早退：绝大多数待定寄存器并不出现在当前操作数文本里，而 replace_word 必然分配。
        // 先用 contains（std 里是 memchr 优化的子串搜索）挡掉，省掉那次分配 + 整段拷贝。
        if !s.contains(n.as_str()) {
            continue;
        }
        s = replace_word(&s, n, &format!("({e})"));
    }
    let _ = rl;
    s
}
