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

use crate::analyzer::{Analyzer, LibGroups};
use capstone::arch;
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
    fn text(&self) -> String {
        match self {
            Expr::Reg(r) => r.clone(),
            Expr::Imm(v) => format!("{v}"),
            Expr::Pool(i) => format!("pp[0x{i:x}]"),
            Expr::Mem(m) => mem_read(m),
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
    analyzer: &Analyzer,
    code: &[u8],
    base: u64,
    is_arm64: bool,
    names: &BTreeMap<u64, String>,
) -> (Vec<Stmt>, String) {
    let rl = roles(analyzer);
    let mut out = Vec::new();
    let mut raw = String::new();
    let mut last_cmp: Option<(String, String)> = None;
    let Ok(insns) = cs.disasm_all(code, base) else {
        return (out, raw);
    };
    for ins in insns.iter() {
        let mnem = ins.mnemonic().unwrap_or("").to_string();
        let ops_masked = mask_regs(&rl, ins.op_str().unwrap_or(""));
        let addr = ins.address();
        let _ = writeln!(raw, "  {addr:#x}: {mnem} {ops_masked}");
        // IR 用**去掉 `#`** 的操作数：`#` 只是汇编的立即数标记，`mem(x2, #0x3f)`、
        // `SP - #8`、`1 << #0` 这类残留会让 Dart 解析器报 expected_token。
        // 反汇编注释块（raw）保留原样，便于与 asm/ 产物逐字对照。
        let ops = ops_masked.replace('#', "");
        if matches!(mnem.as_str(), "cmp" | "cmn" | "tst" | "test" | "fcmp" | "fcmpe") {
            let mut it = ops.split(',');
            let a = it.next().unwrap_or("").trim().to_string();
            let b = it.next().unwrap_or("").trim().to_string();
            // test/tst 的两个操作数相同 ⇒ 与 0 比较（x86 `test al,al`、arm64 `tst x,x`）
            let b = if matches!(mnem.as_str(), "test" | "tst") && b == a { "0".to_string() } else { b };
            last_cmp = Some((a, b));
            // 比较不单独出**语句行**（紧随的条件分支已经把它表达成 `if (a op b)`），
            // 但必须保留下**地址**：`tbz ...; cmp; b.eq` 这类代码的分支目标常常正落在
            // 比较指令上，丢掉它的地址就没有块起点，分支解析不了（曾使 895 个函数
            // 退化成不可结构化）。render_op 对 Cmp 返回 None，故产物里仍不出现。
            out.push(Stmt { addr, op: Op::Cmp });
            continue;
        }
        let s = match lift_one(&rl, is_arm64, &mnem, &ops, addr) {
            Op::Branch { cond: Some(c), target } => {
                // 条件已被这次分支消费：不清空的话，隔着若干条不设标志位的指令后
                // 再来一个 `b.eq` 会错误复用**上一条**比较（拼出假条件）。
                let cond = Some(fold_cond(&c, &last_cmp));
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
                lift_one(&rl, is_arm64, &mnem, &ops, addr)
            }
            other => other,
        };
        out.push(Stmt { addr, op: s });
    }
    (out, raw)
}

/// 条件跳转 + 上一条比较 → 真条件表达式；拼不出来时保留 mnemonic（不猜）。
fn fold_cond(mnem: &str, last: &Option<(String, String)>) -> String {
    let op = match mnem {
        // arm64
        "b.eq" | "b.ne" | "b.lt" | "b.le" | "b.gt" | "b.ge" | "b.hi" | "b.hs" | "b.lo" | "b.ls"
        | "b.mi" | "b.pl" | "b.vs" | "b.vc" => match mnem {
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
            _ => return mnem.to_string(),
        },
        // x86
        "je" | "jz" => "==",
        "jne" | "jnz" => "!=",
        "jl" | "jb" | "jnae" => "<",
        "jle" | "jbe" | "jna" => "<=",
        "jg" | "ja" | "jnbe" => ">",
        "jge" | "jae" | "jnb" => ">=",
        "js" => "<",
        "jns" => ">=",
        _ => return mnem.to_string(),
    };
    match last {
        Some((a, b)) => format!("{a} {op} {b}"),
        None => mnem.to_string(),
    }
}

/// 把寄存器名替换成框架名（PP/THR/SP/FP/LR），内存操作数内部同样替换。
fn mask_regs(rl: &Roles, ops: &str) -> String {
    let mut s = ops.to_string();
    // 先按平台 profile 的 register_aliases 换（x15→SP、x29→FP、x26→THR…），
    // 再补一组与平台无关的通用别名。**别名表按 key 长度倒序**：短名先换会把
    // `x15` 里的 `x1` 之类误伤（历史上 arm64 的 `sp` 因此显示成裸 `x15`）。
    let mut pairs: Vec<(String, String)> = rl
        .aliases
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    pairs.push((rl.pp.clone(), "PP".into()));
    pairs.push((rl.thr.clone(), "THR".into()));
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
    pairs.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    for (k, v) in &pairs {
        s = replace_word(&s, k, v);
    }
    s
}

/// 按「词边界」替换（前后不能是字母数字），避免 `r1` 命中 `r14`。
fn replace_word(s: &str, from: &str, to: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0usize;
    while i < s.len() {
        if b[i..].starts_with(from.as_bytes())
            && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'))
        {
            let j = i + from.len();
            if j >= s.len() || !(b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                out.push_str(to);
                i = j;
                continue;
            }
        }
        out.push(s.as_bytes()[i] as char);
        i += 1;
    }
    out
}

/// 寄存器角色（与 asm 导出同源；按平台 profile 取名）
#[derive(Clone)]
struct Roles {
    pp: String,
    thr: String,
    /// Dart 代码里的栈指针寄存器名（arm64 是 x15 —— SDK constants_arm64.h 的
    /// `R15 = 15; // SP in Dart code.`；x64 是 rsp）
    sp: String,
    /// 平台 profile 的 register_aliases（寄存器名 → 框架名）
    aliases: std::collections::HashMap<String, String>,
}

fn roles(analyzer: &Analyzer) -> Roles {
    let r = &analyzer.platform.registers;
    let g = |k: &str, d: &str| r.get(k).cloned().unwrap_or_else(|| d.to_string());
    Roles {
        pp: g("pp", "pp"),
        thr: g("thr", "thr"),
        sp: g("sp", "sp"),
        aliases: analyzer.platform.register_aliases.clone(),
    }
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
    let ppx = rl.pp.to_uppercase();
    if ops.contains(&ppx) || ops.contains(&rl.pp) {
        if is_reg(&first) {
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
    }
    // 寄存器间 move
    if mnem == "mov" || mnem == "movq" {
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
                    src: Expr::Imm(v as i64),
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
            return Op::Branch {
                cond: Some(format!("{} & (1 << {}) {op} 0", parts[0], parts[1])),
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
    // ---- 条件选择 csel dst, a, b, cond → cond ? a : b ----
    if mnem == "csel" || mnem == "csinc" {
        let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
        if parts.len() == 4 && is_reg(parts[0]) {
            return Op::Assign {
                dst: reg_name(parts[0]),
                src: Expr::Text(format!("({}) ? {} : {}", parts[3], parts[1], parts[2])),
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
    let fbin = match mnem {
        "fadd" => Some("+"),
        "fsub" => Some("-"),
        "fmul" => Some("*"),
        "fdiv" => Some("/"),
        _ => None,
    };
    if let Some(op) = fbin {
        let parts: Vec<&str> = split_operands(&ops).iter().map(|s| s.trim()).collect();
        if parts.len() >= 3 && is_reg(parts[0]) {
            return Op::Assign {
                dst: reg_name(parts[0]),
                src: Expr::Text(format!("({} {op} {}) /* float */", parts[1], parts[2])),
            };
        }
    }
    // ---- 浮点一元/最值/转换：只标注读法，不猜类型 ----
    {
        let parts: Vec<&str> = split_operands(&ops).iter().map(|s| s.trim()).collect();
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
                src: Expr::Text(format!("({} as {})", parts[1], mnem)),
            };
        }
        if mnem == "ubfiz" && parts.len() >= 4 && is_reg(d) {
            let lsb = parse_imm_i(parts[2]).unwrap_or(0);
            let w = parse_imm_i(parts[3]).unwrap_or(0);
            let mask = if w >= 64 { u64::MAX } else { (1u64 << w) - 1 };
            return Op::Assign {
                dst: reg_name(d),
                src: Expr::Text(format!(
                    "(({} & {mask:#x}) << {lsb})",
                    parts[1]
                )),
            };
        }
        // cset dst, cond：条件成立取 1
        if (mnem == "cset" || mnem == "csetm") && parts.len() >= 2 && is_reg(d) {
            return Op::Assign {
                dst: reg_name(d),
                src: Expr::Text(format!("({}) ? {} : 0", parts[1], if mnem == "csetm" { "-1" } else { "1" })),
            };
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
        let base = mem_base(&ops);
        let is_stack = matches!(base, Some(b) if b == rl.sp.as_str() || b == "SP" || b == "sp");
        if is_stack {
            return Op::Note(format!("frame: {ops}"));
        }
        // 3 段 = 两个寄存器 + 一个地址（`ldp x0, x1, [x19, #0x10]`）
        let parts: Vec<&str> = split_operands(&ops);
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
    if mnem == "neg" || mnem == "mvn" {
        if is_reg(&first) && is_reg(&rest) {
            return Op::Assign {
                dst: reg_name(&first),
                src: Expr::Text(format!("-{}", reg_name(&rest))),
            };
        }
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

/// 读内存 → 合法表达式
fn mem_read(operand: &str) -> String {
    let m = mem_parts(operand);
    if let Some(l) = m.local_name() {
        return l;
    }
    format!("mem({})", m.args())
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
        .find(|c| c == ',' || c == ']')
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
    for i in 0..blocks.len() {
        let last = blocks[i].stmts.last().cloned();
        let next = starts.get(i + 1).copied();
        match last.map(|s| s.op) {
            Some(Op::Branch { cond, target }) => {
                if target != 0 && starts.contains(&target) {
                    blocks[i].succs.push((cond.clone(), target));
                }
                if cond.is_some() {
                    if let Some(nx) = next {
                        blocks[i].succs.push((None, nx));
                    }
                }
            }
            Some(Op::Return { .. }) | Some(Op::Abort(_)) => {}
            // brk 也是终止符：不再造落空边（否则结构化器会把它当普通语句，
            // 并为「陷阱之后的字节」连出一条不存在的后续）
            _ => {
                if let Some(nx) = next {
                    blocks[i].succs.push((None, nx));
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
) {
    let mut s = Structurer::new(blocks, rl.clone());
    let nodes = s.seq(0, None);
    let reason = s.reason.clone();
    let mut unstructured = s.unstructured;
    let mut body = String::new();
    render_nodes(&nodes, 0, &mut body, &mut unstructured);
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
                if declared.insert(dst.clone()) {
                    let _ = writeln!(out, "  dynamic {dst};");
                }
            }
            Op::Call { dst: Some(d), .. } => {
                let d = sanitize_regs(d);
                if declared.insert(d.clone()) {
                    let _ = writeln!(out, "  dynamic {d};");
                }
            }
            Op::PairLoad { d1, d2, .. } => {
                for d in [d1, d2] {
                    let d = sanitize_regs(d);
                    if declared.insert(d.clone()) {
                        let _ = writeln!(out, "  dynamic {d};");
                    }
                }
            }
            _ => {}
        }
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
    let cs = build_cs(is_arm64)?;
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
];

/// 位宽/扩展名（`as u8`、`as sxtw` 里的类型位）→ `typedef ... = int;`
const WIDTH_NAMES: &[&str] = &[
    "u8", "u16", "u32", "i8", "i16", "i32", "sxtb", "sxth", "sxtw", "uxtb", "uxth", "uxtw",
];

/// 文件前导：伪运行时 + 用到但本文件没定义的标识符声明。
/// 这一步是「产物能过 `dart analyze`」的关键：寄存器（x0/PP/THR）、跨库调用目标、
/// 机器层占位函数都不是 Dart 内建名字，不声明就是几万条 undefined_identifier。
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
const CHUNK_MAX_BYTES: usize = 256;

fn lift_chunks(
    cs: &Capstone,
    analyzer: &Analyzer,
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
                        .and_then(|o| parse_addr(o))
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
        let (mut cs_stmts, _raw) = lift(cs, analyzer, &keep, t, is_arm64, names);
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

/// 建 capstone 实例。**开 skipdata**：遇到非指令字节（函数入口前的 0 填充、对齐
/// padding）不中断整段反汇编，而是还原成 `.byte ..` 继续走——否则一个坏字节会让
/// 整个函数从产物里消失（实测 `dart compile exe` 的部分函数入口前就带 16 字节 0）。
fn build_cs(is_arm64: bool) -> Result<Capstone, String> {
    let c = if is_arm64 {
        Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()
    } else {
        Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
    }
    .map_err(|e| format!("capstone 初始化失败: {e}"))?;
    let mut c = c;
    c.set_skipdata(true)
        .map_err(|e| format!("capstone skipdata 设置失败: {e}"))?;
    Ok(c)
}

// ---------------------------------------------------------------- entry

pub fn write(
    analyzer: &Analyzer,
    libs: &LibGroups,
    out_dir: &Path,
) -> Result<DecompileStats, String> {
    let (files, stats) = render(analyzer, libs)?;
    let dir = out_dir.join("dart");
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建 dart 目录失败: {e}"))?;
    for (name, text) in files {
        std::fs::write(dir.join(name), text).map_err(|e| format!("写 dart 文件失败: {e}"))?;
    }
    Ok(stats)
}

/// 渲染但不落盘：返回 (文件名, 正文) 列表 + 统计。
/// 子命令要往 stdout 出伪代码，落盘版本只是它的一层包装。
pub fn render(
    analyzer: &Analyzer,
    libs: &LibGroups,
) -> Result<(Vec<(String, String)>, DecompileStats), String> {
    let is_arm64 = analyzer.platform.arch == "arm64";
    let rl = roles(analyzer);
    let cs = build_cs(is_arm64)?;

    let mut files: Vec<(String, String)> = Vec::new();
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
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut used: BTreeMap<String, u32> = BTreeMap::new();
    // 入口地址 → 显示名（与产物里的函数标题一致，首见生效），供 `bl` 目标命名
    let mut names: BTreeMap<u64, String> = BTreeMap::new();
    for (_lib, cls_map) in libs {
        for (_cls, funcs) in cls_map {
            for f in funcs {
                if f.ep == 0 || names.contains_key(&f.ep) {
                    continue;
                }
                let n = dart_ident(
                    &format!(
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
    for idx in 0..analyzer.pc_offsets.len() {
        if let Some((ep, _)) = analyzer.code_range(idx) {
            names.entry(ep).or_insert_with(|| format!("sub_{ep:#x}"));
        }
    }
    for (lib_name, cls_map) in libs {
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
        let mut of = String::new();
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
        for (_cls, funcs) in cls_map {
            for f in funcs {
                if f.ep == 0 || !seen.insert(f.ep) {
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
                let (mut stmts, raw) = lift(&cs, analyzer, code, entry, is_arm64, &names);
                let limit = entry + csize;
                stmts.retain(|s| s.addr < limit);
                if stmts.is_empty() {
                    if std::env::var("DART_AOT_DEBUG_DEC").is_ok() {
                        eprintln!("[dbg-dec] 空 lift: {_cls}.{} ep={:#x} entry={entry:#x} csize={csize}", f.mangled, f.ep);
                    }
                    continue;
                }
                // 共享尾块（跳进别的函数范围又跳回来）也算本函数的一部分
                let (extra, chunks) = lift_chunks(&cs, analyzer, &stmts, is_arm64, &names);
                if !extra.is_empty() {
                    stmts.extend(extra);
                    stmts.sort_by_key(|s| s.addr);
                }
                let blocks = build_blocks(stmts);
                stats.stmts += blocks.iter().map(|b| b.stmts.len()).sum::<usize>();
                stats.blocks += blocks.len();
                for b in &blocks {
                    for st in &b.stmts {
                        match &st.op {
                            Op::Call { target: Some(_), resolved, .. } => {
                                stats.calls += 1;
                                if resolved.is_some() {
                                    stats.calls_named += 1;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                let base = dart_ident(
                    &format!(
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
                emit_function(
                    &name,
                    &blocks,
                    &rl,
                    &mut of,
                    &raw,
                    &chunks,
                    &mut stats.structured,
                    &mut stats.fallback,
                );
                // 未映射行只数**发射出去的**：原来的口径统计所有基本块，
                // 把永远走不到的块也算进去，产物一变就虚高（chunk 之后尤其明显）
                stats.unmapped += of[before..].matches("// unmapped:").count();
                cnt += 1;
            }
        }
        stats.funcs += cnt;
        // 前导声明要在正文全部渲染完之后算（要知道用到哪些标识符、定义了哪些函数）
        let preamble = dart_preamble(&of, &defined);
        let mut full = String::with_capacity(of.len() + preamble.len());
        full.push_str(&preamble);
        full.push_str(&of);
        files.push((fname, full));
    }
    Ok((files, stats))
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
    rl: Roles,
    idx: BTreeMap<u64, usize>,
    loops: BTreeMap<usize, (usize, usize)>, // header idx → (body 入口, 出口)
    in_loop: BTreeMap<usize, usize>,    // block idx → 所属循环头 idx
    done: BTreeSet<usize>,
    /// 发射期当前所在的循环头栈：静态 in_loop 只说明"这个块属于某个循环"，
    /// 但该循环体可能已经在别处发完了；此时再发 `continue` 就跑到循环外面去了
    /// （实测一个 10k 函数应用里有 1 例，dart analyze 报 continue_outside_of_loop）。
    loop_stack: Vec<usize>,
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

/// Cooper–Harvey–Kennedy 支配集迭代
fn dominators(blocks: &[Block], idx: &BTreeMap<u64, usize>) -> Vec<BTreeSet<usize>> {
    let n = blocks.len();
    let mut dom: Vec<BTreeSet<usize>> = vec![(0..n).collect(); n];
    if n == 0 {
        return dom;
    }
    dom[0].clear();
    dom[0].insert(0);
    let mut changed = true;
    while changed {
        changed = false;
        for b in 1..n {
            let mut preds = Vec::new();
            for (p, blk) in blocks.iter().enumerate() {
                // 回边不参与支配计算（经典算法的标准处理）
                if blk.succs.iter().any(|(_, t)| idx.get(t) == Some(&b)) && p != b {
                    preds.push(p);
                }
            }
            let mut newset: Option<BTreeSet<usize>> = None;
            for p in &preds {
                let s = &dom[*p];
                newset = Some(match newset {
                    None => s.clone(),
                    Some(acc) => acc.intersection(s).copied().collect(),
                });
            }
            let mut newset = newset.unwrap_or_default();
            newset.insert(b);
            if newset != dom[b] {
                dom[b] = newset;
                changed = true;
            }
        }
    }
    dom
}

impl<'a> Structurer<'a> {
    fn new(blocks: &'a [Block], rl: Roles) -> Self {
        let idx: BTreeMap<u64, usize> =
            blocks.iter().enumerate().map(|(i, b)| (b.start, i)).collect();
        let dom = dominators(blocks, &idx);
        let mut loops = BTreeMap::new();
        let mut in_loop = BTreeMap::new();
        // 回边 u → h（h 支配 u）⇒ 自然循环体 = {h} ∪ 能不经 h 到达 u 的块
        for (u, blk) in blocks.iter().enumerate() {
            for (_, t) in &blk.succs {
                let Some(&h) = idx.get(t) else { continue };
                if !dom[u].contains(&h) {
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
            Some(Op::Branch { .. }) | Some(Op::Return { .. }) | Some(Op::Abort(_))
        ) as usize;
        let nested = nest_block(&blk.stmts[..n.saturating_sub(cut)], &self.rl);
        for s in &nested {
            if let Some(line) = render_op(&s.op, s.addr) {
                v.push(Node::Line(line));
            }
        }
        v
    }

    /// 该分支是否「自身终止」（沿路只走单后继、最终遇到 return/brk/区域外跳转）。
    /// 用于 if-return 形状：`if (c) { return x; } <继续走另一支>`
    fn terminates(&self, mut b: usize) -> bool {
        for _ in 0..64 {
            match self.term(b) {
                Some(Op::Return { .. }) | Some(Op::Abort(_)) => return true,
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
    fn seq(&mut self, start: usize, stop: Option<usize>) -> Vec<Node> {
        let mut out: Vec<Node> = Vec::new();
        let mut cur = Some(start);
        let mut guard = 0usize;
        while let Some(b) = cur {
            guard += 1;
            if guard > 4096 {
                break;
            }
            if Some(b) == stop || !self.done.insert(b) {
                break;
            }
            // 循环头：条件在循环体内求值，故头块语句进 body
            if let Some(&(_, exit)) = self.loops.get(&b) {
                let (cond, body_entry) = self.loop_shape(b);
                let mut body = self.body_lines(b);
                self.loop_stack.push(b);
                body.extend(self.seq(body_entry, Some(b)));
                self.loop_stack.pop();
                out.push(Node::While { cond, body });
                cur = Some(exit);
                continue;
            }
            out.extend(self.body_lines(b));
            match self.term(b) {
                Some(Op::Return { value }) => {
                    out.push(Node::Line(match &value {
                        Some(v) => format!("return {v};"),
                        None => "return;".to_string(),
                    }));
                    break;
                }
                Some(Op::Abort(n)) => {
                    out.push(Node::Line(format!("abort(); // brk #{n:#x}")));
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
                    match (t, f) {
                        (Some(ti), Some(fi)) => {
                            // 汇合点 == 区域终点也算合法菱形：两支各自走到区域末尾，
                            // 只是不再有「汇合之后」的语句（历史实现把它排除掉，
                            // 白白让 1/4 的 if/else 退回 goto）。
                            if let Some(j) = self.find_join(ti, fi) {
                                let then = self.seq(ti, Some(j));
                                let els = self.seq(fi, Some(j));
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
                                let then = self.seq(ti, stop);
                                out.push(Node::If {
                                    cond: c.clone(),
                                    then,
                                    els: vec![],
                                });
                                cur = Some(fi);
                            } else if self.terminates(fi) {
                                // 镜像形状：else 支终止 → 取反后作为 then 发射
                                let els = self.seq(fi, stop);
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
                                    then: self.seq(ti, stop),
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
                        Some(_) => {
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
    fn loop_shape(&self, h: usize) -> (Option<String>, usize) {
        match self.term(h) {
            Some(Op::Branch { cond: Some(c), target }) => {
                let ti = self.idx.get(&target).copied();
                let fi = self.succ(h, 1);
                let inside = ti.filter(|t| self.in_loop.get(t) == Some(&h));
                let outside = fi.filter(|t| self.in_loop.get(t) != Some(&h));
                if inside.is_some() && outside.is_some() {
                    (Some(c), inside.unwrap())
                } else {
                    (None, self.succ(h, 0).unwrap_or(h))
                }
            }
            _ => (None, self.succ(h, 0).unwrap_or(h)),
        }
    }
}

fn render_nodes(nodes: &[Node], indent: usize, out: &mut String, unstructured: &mut bool) {
    let pad = "  ".repeat(indent + 1);
    for n in nodes {
        match n {
            Node::Line(l) => {
                // Node::Line 也绕过 render_op（结构化器的兜底分支直接拼了字符串），
                // 所以这里再兜一次；对已清洗过的文本是幂等的。
                let l = sanitize_regs(&sanitize_mem_refs(l));
                let _ = writeln!(out, "{pad}{l}");
            }
            Node::If { cond, then, els } => {
                // 条件文本绕过 render_op（不经过那边的 sanitize），单独过一遍：
                // x86 的 `qword ptr [THR + 0x40]` 直接进 `if (...)` 就是语法错误
                let cond = sanitize_regs(&sanitize_mem_refs(cond));
                let _ = writeln!(out, "{pad}if ({cond}) {{");
                render_nodes(then, indent + 1, out, unstructured);
                if els.is_empty() {
                    let _ = writeln!(out, "{pad}}}");
                } else {
                    let _ = writeln!(out, "{pad}}} else {{");
                    render_nodes(els, indent + 1, out, unstructured);
                    let _ = writeln!(out, "{pad}}}");
                }
            }
            Node::While { cond, body: _ } => match cond {
                Some(c) => {
                    let c = sanitize_regs(&sanitize_mem_refs(c));
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
            render_nodes(body, indent + 1, out, unstructured);
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
fn render_op(op: &Op, addr: u64) -> Option<String> {
    let line = render_op_inner(op, addr)?;
    Some(sanitize_regs(&sanitize_mem_refs(&line)))
}

fn render_op_inner(op: &Op, addr: u64) -> Option<String> {
    match op {
        Op::Assign { dst, src } => Some(format!("{dst} = {}; // {addr:#x}", src.text())),
        Op::Cmp => None,
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
            Op::Note(_) | Op::Abort(_) | Op::Other(_) | Op::Cmp | Op::PairLoad { .. } => {
                out.push(Stmt { addr: st.addr, op: st.op.clone() });
                pending.clear();
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
                            mem_read(&subst_regs(m, &pending, rl))
                        } else {
                            mem_read(m)
                        }
                    }
                    Expr::Text(x) => x.clone(),
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
        // 纯寄存器别名（如 FP = SP）不做替换：语义等价但可读性更差
        if e.split(|c: char| !c.is_ascii_alphanumeric()).filter(|s| !s.is_empty()).count() == 1
            && !e.contains('[')
            && !e.contains('+')
        {
            continue;
        }
        s = replace_word(&s, n, &format!("({e})"));
    }
    let _ = rl;
    s
}
