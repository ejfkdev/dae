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
struct Edge {
    from: u64,
    from_name: String,
    kind: &'static str, // "direct" | "indirect"
    to: Option<u64>,    // indirect 时为 None
    to_text: String,    // 直接调用：目标地址文本；间接：操作数原文
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

    // ep → 完整名（lib.Class.member），用于把调用目标落回名字
    let mut name_of: BTreeMap<u64, String> = BTreeMap::new();
    let mut plan: Vec<(u64, u64, u64, String)> = Vec::new(); // (ep, payload, csize, name)
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    for (lib_name, cls_map) in libs {
        for (cls_name, funcs) in cls_map {
            for f in funcs {
                if f.ep == 0 || f.idx >= analyzer.pc_offsets.len() {
                    continue;
                }
                let full = if cls_name.is_empty() {
                    format!("{lib_name}.{}", f.mangled)
                } else {
                    format!("{lib_name}.{cls_name}.{}", f.mangled)
                };
                name_of.entry(f.ep).or_insert_with(|| full.clone());
                if !seen.insert(f.ep) {
                    continue;
                }
                let csize = analyzer.code_size(f.idx);
                if csize == 0 {
                    continue;
                }
                let payload = analyzer.instr_base + analyzer.pc_offsets[f.idx];
                let foff = payload + analyzer.slice_off;
                if foff as usize + csize as usize > analyzer.data.len() {
                    continue;
                }
                plan.push((f.ep, payload, csize, full));
            }
        }
    }

    let is_arm64 = analyzer.platform.arch == "arm64";
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
    let data = analyzer.data;
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
                    Ok(c) => c,
                    Err(e) => {
                        let _ = tx.send((pi, Vec::new(), Some(format!("capstone 初始化失败: {e}"))));
                        return;
                    }
                };
                let mut out: Vec<Edge> = Vec::new();
                for &(ep, payload, csize, ref fname) in &plan_ref[b..e] {
                    let code = &data[payload as usize..(payload + csize) as usize];
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
    for (pi, v, err) in rx {
        if let Some(e) = err {
            return Err(e);
        }
        parts[pi] = Some(v);
    }
    let mut edges: Vec<Edge> = Vec::new();
    for p in parts.into_iter().flatten() {
        edges.extend(p);
    }
    edges.sort_by(|a, b| (a.from, a.to, a.to_text.clone()).cmp(&(b.from, b.to, b.to_text.clone())));

    // ---- text/call_edges.txt ----
    let mut txt = String::with_capacity(edges.len() * 72);
    let (mut n_direct, mut n_indirect, mut n_resolved) = (0usize, 0usize, 0usize);
    for e in &edges {
        match e.kind {
            "direct" => {
                let to = e.to.unwrap_or(0);
                let to_name = name_of.get(&to).map(|s| s.as_str()).unwrap_or("");
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
            Some(t) if name_of.contains_key(&t) => t,
            _ => continue, // 只画库内有名字的目标，避免把外部地址画成孤立点
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
        let label = name_of
            .get(n)
            .map(|s| s.replace('"', "'"))
            .unwrap_or_else(|| format!("0x{n:x}"));
        let _ = writeln!(dot, "  n{n:x} [label=\"{label}\"];");
    }
    for (a, b) in &dot_edges {
        let _ = writeln!(dot, "  n{a:x} -> n{b:x};");
    }
    dot.push_str("}\n");
    std::fs::write(out_dir.join("callgraph.dot"), dot)
        .map_err(|e| format!("写 callgraph.dot 失败: {e}"))?;

    Ok(CallGraphCounts {
        funcs: plan.len(),
        direct: n_direct,
        edges_resolved: n_resolved,
        indirect: n_indirect,
    })
}