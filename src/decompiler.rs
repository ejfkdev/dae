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
}

impl Expr {
    fn text(&self) -> String {
        match self {
            Expr::Reg(r) => r.clone(),
            Expr::Imm(v) => format!("{v}"),
            Expr::Pool(i) => format!("pp[0x{i:x}]"),
            Expr::Mem(m) => format!("mem({m})"),
        }
    }
}

#[derive(Clone, Debug)]
enum Op {
    Assign { dst: String, src: Expr },
    /// 直接调用（target = 目标地址）；间接调用 target = None、callee 为操作数原文
    Call { dst: Option<String>, target: Option<u64>, callee: String },
    /// cond = None 表示无条件跳转
    Branch { cond: Option<String>, target: u64 },
    Return { value: Option<String> },
    /// 认不出来的指令：原文保留
    Other(String),
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
fn lift(cs: &Capstone, analyzer: &Analyzer, code: &[u8], base: u64, is_arm64: bool) -> (Vec<Stmt>, String) {
    let rl = roles(analyzer);
    let mut out = Vec::new();
    let mut raw = String::new();
    let mut last_cmp: Option<(String, String)> = None;
    let Ok(insns) = cs.disasm_all(code, base) else {
        return (out, raw);
    };
    for ins in insns.iter() {
        let mnem = ins.mnemonic().unwrap_or("").to_string();
        let ops = mask_regs(&rl, ins.op_str().unwrap_or(""));
        let addr = ins.address();
        let _ = writeln!(raw, "  {addr:#x}: {mnem} {ops}");
        if mnem == "cmp" || mnem == "test" {
            let mut it = ops.split(',');
            let a = it.next().unwrap_or("").trim().to_string();
            let b = it.next().unwrap_or("").trim().to_string();
            let b = if mnem == "test" && b == a { "0".to_string() } else { b };
            last_cmp = Some((a, b));
            out.push(Stmt { addr, op: Op::Other(format!("{mnem} {ops}")) });
            continue;
        }
        let s = match lift_one(&rl, is_arm64, &mnem, &ops, addr) {
            Op::Branch { cond: Some(c), target } => Op::Branch {
                cond: Some(fold_cond(&c, &last_cmp)),
                target,
            },
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
    // 长的先换，避免 `r14` 命中 `r1`
    let mut pairs: Vec<(String, &str)> = vec![
        (rl.pp.clone(), "PP"),
        (rl.thr.clone(), "THR"),
        ("x29".into(), "FP"),
        ("x30".into(), "LR"),
    ];
    for (k, v) in &pairs {
        s = replace_word(&s, k, v);
    }
    pairs.clear();
    let _ = pairs;
    for (k, v) in [("rbp", "FP"), ("rsp", "SP"), ("esp", "SP"), ("ebp", "FP")] {
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
struct Roles {
    pp: String,
    thr: String,
}

fn roles(analyzer: &Analyzer) -> Roles {
    let r = &analyzer.platform.registers;
    let g = |k: &str, d: &str| r.get(k).cloned().unwrap_or_else(|| d.to_string());
    Roles {
        pp: g("pp", "pp"),
        thr: g("thr", "thr"),
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
        let t = parse_imm(ops);
        return Op::Call {
            dst: None,
            target: t,
            callee: ops.trim().to_string(),
        };
    }
    if mnem == "blr" {
        return Op::Call {
            dst: None,
            target: None,
            callee: reg_name(ops.trim()),
        };
    }
    // 条件/无条件跳转
    if mnem == "b" || mnem == "jmp" {
        if let Some(t) = parse_imm(ops) {
            return Op::Branch { cond: None, target: t };
        }
        return Op::Branch {
            cond: None,
            target: 0,
        };
    }
    if mnem.starts_with("b.") || (mnem.starts_with('j') && mnem != "jmp") {
        let t = parse_imm(ops).unwrap_or(0);
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
            if let Some(v) = parse_imm(&rest) {
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
    // 加载：ldr/ldur/movzx 等 → 目标寄存器 + 内存表达式原文
    if is_reg(&first) && (mnem.starts_with("ldr") || mnem.starts_with("ldur") || mnem.starts_with("ld")) && is_arm64
    {
        return Op::Assign {
            dst: reg_name(&first),
            src: Expr::Mem(rest.clone()),
        };
    }
    let _ = addr;
    Op::Other(format!("{mnem} {ops}").trim().to_string())
}

fn parse_imm(ops: &str) -> Option<u64> {
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
            Some(Op::Return { .. }) => {}
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

fn emit_function(
    name: &str,
    blocks: &[Block],
    out: &mut String,
    raw: &str,
    structured: &mut usize,
    fallback: &mut usize,
) {
    let mut s = Structurer::new(blocks);
    let nodes = s.seq(0, None);
    let mut unstructured = s.unstructured;
    let mut body = String::new();
    render_nodes(&nodes, 0, &mut body, &mut unstructured);
    if unstructured {
        *fallback += 1;
    } else {
        *structured += 1;
    }

    let _ = writeln!(out, "\n// {name}");
    let _ = writeln!(out, "// raw disassembly:");
    out.push_str("//");
    out.push_str(&raw.replace('\n', "\n//"));
    out.push('\n');
    if unstructured {
        let _ = writeln!(
            out,
            "// NOTE: control flow was not fully structured (goto kept) — pseudocode only."
        );
    }
    let _ = writeln!(out, "dynamic {name}() {{");
    let mut declared: BTreeSet<String> = BTreeSet::new();
    for st in blocks.iter().flat_map(|b| b.stmts.iter()) {
        match &st.op {
            Op::Assign { dst, .. } => {
                if declared.insert(dst.clone()) {
                    let _ = writeln!(out, "  dynamic {dst};");
                }
            }
            Op::Call { dst: Some(d), .. } => {
                if declared.insert(d.clone()) {
                    let _ = writeln!(out, "  dynamic {d};");
                }
            }
            _ => {}
        }
    }
    out.push_str(&body);
    out.push_str("}\n");
}

// ---------------------------------------------------------------- entry

pub fn write(
    analyzer: &Analyzer,
    libs: &LibGroups,
    out_dir: &Path,
) -> Result<DecompileStats, String> {
    let dir = out_dir.join("dart");
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建 dart 目录失败: {e}"))?;
    let is_arm64 = analyzer.platform.arch == "arm64";
    let cs = if is_arm64 {
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

    let mut stats = DecompileStats {
        funcs: 0,
        blocks: 0,
        stmts: 0,
        structured: 0,
        fallback: 0,
    };
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut used: BTreeMap<String, u32> = BTreeMap::new();
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
        let _ = writeln!(
            of,
            "// dae decompiler output — pseudocode, not compilable Dart"
        );
        let _ = writeln!(of, "// library: {lib_name}");
        let _ = writeln!(
            of,
            "// block labels and `goto` stand in for control flow that this stage does not restructure yet."
        );
        let mut cnt = 0usize;
        for (_cls, funcs) in cls_map {
            for f in funcs {
                if f.ep == 0 || !seen.insert(f.ep) {
                    continue;
                }
                let csize = analyzer.code_size(f.idx);
                if csize == 0 || f.idx >= analyzer.pc_offsets.len() {
                    continue;
                }
                let payload = analyzer.instr_base + analyzer.pc_offsets[f.idx];
                let foff = payload + analyzer.slice_off;
                if foff as usize + csize as usize > analyzer.data.len() {
                    continue;
                }
                let code = &analyzer.data[foff as usize..(foff + csize) as usize];
                let (stmts, raw) = lift(&cs, analyzer, code, payload, is_arm64);
                if stmts.is_empty() {
                    continue;
                }
                let blocks = build_blocks(stmts);
                stats.stmts += blocks.iter().map(|b| b.stmts.len()).sum::<usize>();
                stats.blocks += blocks.len();
                let name = format!("{}_{}", _cls.replace(['.', ':'], "_"), f.mangled)
                    .trim_start_matches('_')
                    .to_string();
                emit_function(
                    &name,
                    &blocks,
                    &mut of,
                    &raw,
                    &mut stats.structured,
                    &mut stats.fallback,
                );
                cnt += 1;
            }
        }
        stats.funcs += cnt;
        std::fs::write(dir.join(fname), of).map_err(|e| format!("写 dart 文件失败: {e}"))?;
    }
    Ok(stats)
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
    idx: BTreeMap<u64, usize>,
    loops: BTreeMap<usize, (usize, usize)>, // header idx → (body 入口, 出口)
    in_loop: BTreeMap<usize, usize>,    // block idx → 所属循环头 idx
    done: BTreeSet<usize>,
    unstructured: bool,
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
    fn new(blocks: &'a [Block]) -> Self {
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
            idx,
            loops,
            in_loop,
            done: BTreeSet::new(),
            unstructured: false,
        }
    }

    /// 一条边的目标块下标
    fn succ(&self, b: usize, k: usize) -> Option<usize> {
        self.blocks[b].succs.get(k).and_then(|(_, t)| self.idx.get(t).copied())
    }

    fn term(&self, b: usize) -> Option<Op> {
        self.blocks[b].stmts.last().map(|s| s.op.clone())
    }

    /// 语句渲染（不含最后一条终结指令）
    fn body_lines(&self, b: usize) -> Vec<Node> {
        let mut v = Vec::new();
        let n = self.blocks[b].stmts.len();
        let cut = matches!(
            self.term(b),
            Some(Op::Branch { .. }) | Some(Op::Return { .. })
        ) as usize;
        for s in &self.blocks[b].stmts[..n.saturating_sub(cut)] {
            if let Some(line) = render_op(&s.op, s.addr) {
                v.push(Node::Line(line));
            }
        }
        v
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
                body.extend(self.seq(body_entry, Some(b)));
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
                Some(Op::Branch { cond: Some(c), target }) => {
                    let t = self.idx.get(&target).copied();
                    let f = self.succ(b, 1);
                    // 循环内：出口边 → break；回边 → continue
                    let in_l = self.in_loop.get(&b).copied();
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
                            if let Some(j) = self.find_join(ti, fi).filter(|j| Some(*j) != stop) {
                                let then = self.seq(ti, Some(j));
                                let els = self.seq(fi, Some(j));
                                out.push(Node::If {
                                    cond: c.clone(),
                                    then,
                                    els,
                                });
                                cur = Some(j);
                            } else {
                                // 汇合不了：只保留 true 支，其余退回 goto
                                self.unstructured = true;
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
                            self.unstructured = true;
                            out.push(Node::Line(format!("if ({c}) {{ /* 目标越界 */ }}")));
                            break;
                        }
                    }
                }
                Some(Op::Branch { cond: None, target }) => {
                    let t = self.idx.get(&target).copied();
                    if t == stop {
                        break;
                    }
                    if let Some(h) = self.in_loop.get(&b) {
                        if self.loops.contains_key(&h) && t == Some(*h) {
                            out.push(Node::Continue);
                            break;
                        }
                    }
                    match t {
                        Some(ti) if Some(ti) == self.succ(b, 0).or(Some(ti)) => {
                            cur = t;
                        }
                        other => {
                            match other {
                                Some(ti) if !self.done.contains(&ti) => {
                                    cur = Some(ti);
                                }
                                _ => {
                                    out.push(Node::Goto(self.blocks[b].succs[0].1));
                                    break;
                                }
                            }
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
                let _ = writeln!(out, "{pad}{l}");
            }
            Node::If { cond, then, els } => {
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
                let _ = writeln!(out, "{pad}goto L{a:x};");
            }
        }
        if let Node::While { body, .. } = n {
            render_nodes(body, indent + 1, out, unstructured);
            let _ = writeln!(out, "{pad}}}");
        }
    }
}

/// 单条 IR → 伪代码行（None = 不产出，如无跳转意义的指令）
fn render_op(op: &Op, addr: u64) -> Option<String> {
    match op {
        Op::Assign { dst, src } => Some(format!("{dst} = {}; // {addr:#x}", src.text())),
        Op::Call {
            dst, target, callee, ..
        } => {
            let call = match target {
                Some(t) => format!("call 0x{t:x}"),
                None => format!("callIndirect({callee})"),
            };
            Some(match dst {
                Some(d) => format!("{d} = {call}; // {addr:#x}"),
                None => format!("{call}; // {addr:#x}"),
            })
        }
        Op::Branch { .. } | Op::Return { .. } => None,
        Op::Other(t) => Some(format!("// unmapped: {t} // {addr:#x}")),
    }
}
