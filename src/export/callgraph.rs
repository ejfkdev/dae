//! 调用图：从指令流里抽直接调用（arm64 `bl` / x64 `call imm`）与间接调用点
//! （arm64 `blr` / x64 `call reg|mem`），解析目标命名的边写成文本 + DOT。
//!
//! 原则与产物口径一致：**不猜**。间接调用的目标解析不了就如实记为 `indirect`
//! （寄存器/内存操作数原样写出），绝不填一个像模像样的假目标。
//!
//! 产物：
//! - `text/call_edges.txt`  每行 `0xfrom <tab> from_name <tab> kind <tab> 0xto <tab> to_name`
//! - `callgraph.dot`        直接调用图（仅含本二进制内已命名目标，边数有上限）

use crate::analyzer::{Analyzer, LibGroups};
use capstone::arch;
use capstone::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

/// DOT 里最多画多少个节点 / 边（真机产物可达十几万边，不设限没法用）
const DOT_MAX_NODES: usize = 4000;
const DOT_MAX_EDGES: usize = 12000;

pub struct CallGraphCounts {
    pub funcs: usize,
    pub direct: usize,
    /// 解析到本地命名函数的直接边（其余目标多为分配 stub，见 README 限制）
    pub edges_resolved: usize,
    pub indirect: usize,
}

/// 一条边/一个调用点
pub struct Edge {
    /// 调用指令自身的地址（`callers` 用它定位调用点）
    pub at: u64,
    pub from: u64,
    pub from_name: String,
    pub kind: &'static str, // "direct" | "indirect"
    pub to: Option<u64>,    // indirect 时为 None
    /// 间接调用：操作数原文（寄存器/内存式）
    pub to_text: String,
}

fn call_kind(mnem: &str) -> Option<&'static str> {
    // arm64: bl（直接）/ blr（间接）；x64: call（看操作数）
    match mnem {
        "bl" => Some("direct"),
        "blr" => Some("indirect"),
        "call" | "callq" => Some("call?"), // 由操作数决定
        _ => None,
    }
}

/// x86 操作数是立即数 → 直接调用；寄存器/内存 → 间接。
fn x86_direct_target(ops: &str) -> Option<u64> {
    let s = ops.trim();
    let h = s.strip_prefix("0x")?;
    let h = h.split(|c: char| !c.is_ascii_hexdigit()).next()?;
    u64::from_str_radix(h, 16).ok()
}

/// ep → 完整名（`lib.Class.member`）。名字来自 Code 对象；指令表里没有名字的入口
/// 用 `sub_0x...` 占位——与 dart/ 伪代码的命名口径一致，便于两边对照。
pub fn name_map(analyzer: &Analyzer, libs: &LibGroups) -> BTreeMap<u64, String> {
    let mut name_of: BTreeMap<u64, String> = BTreeMap::new();
    for (lib_name, cls_map) in libs {
        for (cls_name, funcs) in cls_map {
            for f in funcs {
                if f.ep == 0 {
                    continue;
                }
                let full = if cls_name.is_empty() {
                    format!("{lib_name}.{}", f.mangled)
                } else {
                    format!("{lib_name}.{cls_name}.{}", f.mangled)
                };
                name_of.entry(f.ep).or_insert(full);
            }
        }
    }
    for idx in 0..analyzer.pc_offsets.len() {
        if let Some((ep, _)) = analyzer.code_range(idx) {
            name_of.entry(ep).or_insert_with(|| format!("sub_{ep:#x}"));
        }
    }
    name_of
}

/// 要扫描的函数计划：(ep, payload, csize, 完整名)，按 ep 去重且保持 libs 顺序。
pub fn plan_functions(
    analyzer: &Analyzer,
    libs: &LibGroups,
) -> Vec<(u64, u64, u64, String)> {
    let mut plan: Vec<(u64, u64, u64, String)> = Vec::new();
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    for (lib_name, cls_map) in libs {
        for (cls_name, funcs) in cls_map {
            for f in funcs {
                if f.ep == 0 || f.idx >= analyzer.pc_offsets.len() || !seen.insert(f.ep) {
                    continue;
                }
                let Some((payload, csize)) = analyzer.code_range(f.idx) else {
                    continue;
                };
                if payload as usize + csize as usize > analyzer.data.len() {
                    continue;
                }
                let full = if cls_name.is_empty() {
                    format!("{lib_name}.{}", f.mangled)
                } else {
                    format!("{lib_name}.{cls_name}.{}", f.mangled)
                };
                plan.push((f.ep, payload, csize, full));
            }
        }
    }
    plan
}

/// 收集全部调用点（直接 + 间接）。`callers` 等查询子命令复用它。
pub fn collect_edges(analyzer: &Analyzer, libs: &LibGroups) -> Vec<Edge> {
    let plan = plan_functions(analyzer, libs);
    let is_arm64 = analyzer.platform.arch == "arm64";
    let data = analyzer.data;
    let slice_off = analyzer.slice_off;
    let n_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(8)
        .max(1);
    let chunk = plan.len().div_ceil(n_threads).max(1);
    let ranges: Vec<(usize, usize)> = (0..plan.len())
        .step_by(chunk)
        .map(|b| (b, (b + chunk).min(plan.len())))
        .collect();
    let (tx, rx) = std::sync::mpsc::channel();
    let plan_ref = &plan;
    std::thread::scope(|scope| {
        for (pi, &(b, e)) in ranges.iter().enumerate() {
            let tx = tx.clone();
            scope.spawn(move || {
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
                };
                let cs = match cs {
                    Ok(mut c) => {
                        if let Err(e) = c.set_skipdata(true) {
                            let _ = tx.send((pi, Vec::new(), Some(format!("capstone skipdata: {e}"))));
                            return;
                        }
                        c
                    }
                    Err(e) => {
                        let _ = tx.send((pi, Vec::new(), Some(format!("capstone 初始化失败: {e}"))));
                        return;
                    }
                };
                let mut out: Vec<Edge> = Vec::new();
                for &(ep, payload, csize, ref fname) in &plan_ref[b..e] {
                    let foff = payload + slice_off;
                    // 用 u64 判，且避免任何加法回绕（`foff + csize` 回绕会绕过检查）
                    let end = match foff.checked_add(csize) {
                        Some(e) => e,
                        None => continue,
                    };
                    if end > data.len() as u64 {
                        continue;
                    }
                    let code = &data[foff as usize..(foff + csize) as usize];
                    let Ok(insns) = cs.disasm_all(code, payload) else { continue };
                    for ins in insns.iter() {
                        let Some(mnem) = ins.mnemonic() else { continue };
                        let Some(k) = call_kind(mnem) else { continue };
                        let ops = ins.op_str().unwrap_or("");
                        let (kind, to) = if k == "call?" {
                            match x86_direct_target(ops) {
                                Some(t) => ("direct", Some(t)),
                                None => ("indirect", None),
                            }
                        } else if k == "direct" {
                            ("direct", arm64_direct_target(ops))
                        } else {
                            ("indirect", None)
                        };
                        out.push(Edge {
                            at: ins.address(),
                            from: ep,
                            from_name: fname.clone(),
                            kind,
                            to,
                            to_text: ops.trim().to_string(),
                        });
                    }
                }
                let _ = tx.send((pi, out, None));
            });
        }
        drop(tx);
    });
    let mut parts: Vec<Option<Vec<Edge>>> = (0..ranges.len()).map(|_| None).collect();
    for (pi, v, _err) in rx {
        parts[pi] = Some(v);
    }
    let mut edges: Vec<Edge> = Vec::new();
    for p in parts.into_iter().flatten() {
        edges.extend(p);
    }
    edges.sort_by(|a, b| (a.from, a.to, a.to_text.clone()).cmp(&(b.from, b.to, b.to_text.clone())));
    edges
}

/// arm64 `bl 0x...` 的操作数就是立即数地址；`blr x8` 是寄存器。
fn arm64_direct_target(ops: &str) -> Option<u64> {
    let s = ops.trim().trim_start_matches('#');
    let h = s.strip_prefix("0x")?;
    let h = h.split(|c: char| !c.is_ascii_hexdigit()).next()?;
    u64::from_str_radix(h, 16).ok()
}

pub fn write(analyzer: &Analyzer, libs: &LibGroups, out_dir: &Path) -> Result<CallGraphCounts, String> {
    let text_dir = out_dir.join("text");
    std::fs::create_dir_all(&text_dir).map_err(|e| format!("创建 text 目录失败: {e}"))?;

    let name_of = name_map(analyzer, libs);
    let n_funcs = plan_functions(analyzer, libs).len();

    let is_arm64 = analyzer.platform.arch == "arm64";
    let edges = collect_edges(analyzer, libs);

    // ---- 分配 stub 命名 ----
    // 直接目标里相当一部分是「每类分配 stub」：它们没有 Function 包装，因此不在
    // 导出名表里。但 stub 序言会把类 id 的 tag 字写进寄存器，可以就地解出来再
    // 映射到类名——只有 cid 命中已知类名时才命名，否则留空（不猜）。
    let stub_names = name_alloc_stubs(analyzer, &edges, &name_of, is_arm64);
    let resolve = |to: u64| -> &str {
        if let Some(n) = name_of.get(&to) {
            return n.as_str();
        }
        stub_names.get(&to).map(|s| s.as_str()).unwrap_or("")
    };

    // ---- text/call_edges.txt ----
    let mut txt = String::with_capacity(edges.len() * 72);
    let (mut n_direct, mut n_indirect, mut n_resolved) = (0usize, 0usize, 0usize);
    for e in &edges {
        match e.kind {
            "direct" => {
                let to = e.to.unwrap_or(0);
                let to_name = resolve(to);
                if !to_name.is_empty() {
                    n_resolved += 1;
                }
                let _ = writeln!(
                    txt,
                    "0x{:x}\t{}\tdirect\t0x{:x}\t{}",
                    e.from, e.from_name, to, to_name
                );
                n_direct += 1;
            }
            _ => {
                let _ = writeln!(
                    txt,
                    "0x{:x}\t{}\tindirect\t{}\t",
                    e.from, e.from_name, e.to_text
                );
                n_indirect += 1;
            }
        }
    }
    std::fs::write(text_dir.join("call_edges.txt"), txt)
        .map_err(|e| format!("写 call_edges.txt 失败: {e}"))?;

    // ---- callgraph.dot（只画解析到名字的直接边，且按节点/边上限裁剪）----
    let mut nodes: BTreeSet<u64> = BTreeSet::new();
    let mut dot_edges: Vec<(u64, u64)> = Vec::new();
    for e in &edges {
        if e.kind != "direct" {
            continue;
        }
        let to = match e.to {
            Some(t) if !resolve(t).is_empty() => t,
            _ => continue, // 只画解析到名字的目标，避免把外部地址画成孤立点
        };
        if !nodes.contains(&e.from) && nodes.len() >= DOT_MAX_NODES {
            continue;
        }
        nodes.insert(e.from);
        nodes.insert(to);
        dot_edges.push((e.from, to));
        if dot_edges.len() >= DOT_MAX_EDGES {
            break;
        }
    }
    let mut dot = String::with_capacity(dot_edges.len() * 48);
    dot.push_str("// dae call graph — direct calls (bl / call imm) between named functions\n");
    dot.push_str("digraph dae_callgraph {\n  rankdir=LR;\n  node [shape=box, fontsize=10];\n");
    for n in &nodes {
        let label = {
            let s = resolve(*n);
            if s.is_empty() {
                format!("0x{n:x}")
            } else {
                s.replace('"', "'")
            }
        };
        let _ = writeln!(dot, "  n{n:x} [label=\"{label}\"];");
    }
    for (a, b) in &dot_edges {
        let _ = writeln!(dot, "  n{a:x} -> n{b:x};");
    }
    dot.push_str("}\n");
    std::fs::write(out_dir.join("callgraph.dot"), dot)
        .map_err(|e| format!("写 callgraph.dot 失败: {e}"))?;

    Ok(CallGraphCounts {
        funcs: n_funcs,
        direct: n_direct,
        edges_resolved: n_resolved,
        indirect: n_indirect,
    })
}
// ---------- 分配 stub 命名 ----------

/// 操作数里第一个立即数（`#0x..` / `#12` / `0x..` 都认）。
fn first_imm(ops: &str) -> Option<u64> {
    for (i, _) in ops.match_indices('#') {
        let tok: String = ops[i + 1..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        if let Some(h) = tok.strip_prefix("0x") {
            if let Ok(v) = u64::from_str_radix(h, 16) {
                return Some(v);
            }
        } else if let Ok(v) = tok.parse::<u64>() {
            return Some(v);
        }
    }
    if let Some(i) = ops.find("0x") {
        let h: String = ops[i + 2..]
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .collect();
        if let Ok(v) = u64::from_str_radix(&h, 16) {
            return Some(v);
        }
    }
    None
}

/// 类名层是否可信。
///
/// 分配 stub 的名字完全来自 `cname_by_cid`；若该表本身没解析出来（2.16.x 上就有这种
/// 情况：cid 为 -1、名字是 `?` 或明显错位的短词），从这里取名等于编造。宁可整体放弃
/// stub 命名——覆盖率会体现出来，但不会有假名。
fn class_layer_usable(analyzer: &Analyzer) -> bool {
    let total = analyzer.cname_by_cid.len();
    if total == 0 {
        return false;
    }
    let bad = analyzer
        .cname_by_cid
        .values()
        .filter(|n| n.is_empty() || n.as_str() == "?")
        .count();
    bad * 2 < total
}

fn build_cs(is_arm64: bool) -> Result<Capstone, String> {
    if is_arm64 {
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
    .map_err(|e| format!("capstone 初始化失败: {e}"))
    .and_then(|mut c| {
        c.set_skipdata(true)
            .map_err(|e| format!("capstone skipdata 设置失败: {e}"))?;
        Ok(c)
    })
}

/// 从 stub 序言解出「被分配的类」→ 名字。
///
/// arm64 形如 `mov xD, #lo` + `movk xD, #hi, lsl #16`（汇编器拼 32 位常量的固定写法，
/// 目标寄存器必须同一个，且必须带 `lsl #16`——否则第二次写是覆盖而非拼接）；
/// x64 形如 `mov r8d, imm32` + `call ...`（tag 字直接用 32 位立即数装载）。
/// 解出的 cid 只有命中已知类名才返回名字，否则 None（**不猜**）。
fn alloc_stub_name(analyzer: &Analyzer, cs: &Capstone, addr: u64, is_arm64: bool) -> Option<String> {
    let foff = addr + analyzer.slice_off;
    let data = analyzer.data;
    if foff >= data.len() as u64 {
        return None;
    }
    let end = (foff + 24).min(data.len() as u64);
    let code = &data[foff as usize..end as usize];
    let insns = cs.disasm_all(code, addr).ok()?;
    let v: Vec<_> = insns.iter().collect();
    let (i0, i1) = (*v.first()?, *v.get(1)?);
    let m0 = i0.mnemonic()?.to_ascii_lowercase();
    if m0 != "mov" {
        return None;
    }
    let o0 = i0.op_str()?;
    let tag = if is_arm64 {
        if i1.mnemonic()?.to_ascii_lowercase() != "movk" {
            return None;
        }
        let o1 = i1.op_str()?;
        let d0 = o0.split(',').next()?.trim();
        if o1.split(',').next()?.trim() != d0 || !o1.contains("lsl #16") {
            return None;
        }
        first_imm(o0)? | (first_imm(o1)? << 16)
    } else {
        let m1 = i1.mnemonic()?.to_ascii_lowercase();
        if m1 != "call" && m1 != "jmp" {
            return None;
        }
        first_imm(o0)?
    };
    let tg = &analyzer.profile.tagging;
    let cid = (tag >> tg.cid_tag_pos) & tg.cid_tag_mask;
    let name = analyzer.cname_by_cid.get(&(cid as i64))?;
    // 只认真正的类标识符：空名与 `?`（名字层没解析出来时的占位）一律不算——
    // 宁可留空，也不产出一个「看起来解出来了」的假名。
    if name.is_empty() || name == "?" || !name.chars().any(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(format!("AllocationStub_{name}"))
}

/// 对每个「没落进导出名表」的直接目标试一次分配 stub 识别。
fn name_alloc_stubs(
    analyzer: &Analyzer,
    edges: &[Edge],
    name_of: &BTreeMap<u64, String>,
    is_arm64: bool,
) -> BTreeMap<u64, String> {
    let mut targets: BTreeSet<u64> = BTreeSet::new();
    for e in edges {
        if e.kind != "direct" {
            continue;
        }
        if let Some(t) = e.to {
            if !name_of.contains_key(&t) {
                targets.insert(t);
            }
        }
    }
    let mut out = BTreeMap::new();
    if targets.is_empty() || !class_layer_usable(analyzer) {
        return out;
    }
    let Ok(cs) = build_cs(is_arm64) else {
        return out;
    };
    for t in targets {
        if let Some(n) = alloc_stub_name(analyzer, &cs, t, is_arm64) {
            out.insert(t, n);
        }
    }
    out
}

/// 对给定地址批量尝试分配 stub 识别——供真值门禁复用（不经过导出管线）。
/// 返回与输入等长的 (地址, 名字) 列表；识别不出时为 None（不猜）。
pub fn alloc_stubs_at(analyzer: &Analyzer, addrs: &[u64]) -> Vec<(u64, Option<String>)> {
    let is_arm64 = analyzer.platform.arch == "arm64";
    if !class_layer_usable(analyzer) {
        return addrs.iter().map(|a| (*a, None)).collect();
    }
    let Ok(cs) = build_cs(is_arm64) else {
        return addrs.iter().map(|a| (*a, None)).collect();
    };
    addrs
        .iter()
        .map(|a| (*a, alloc_stub_name(analyzer, &cs, *a, is_arm64)))
        .collect()
}
