//! 调用图：从指令流里抽直接调用（arm64 `bl` / x64 `call imm`）与间接调用点
//! （arm64 `blr` / x64 `call reg|mem`），解析目标命名的边写成文本 + DOT。
//!
//! 原则与产物口径一致：**不猜**。间接调用的目标解析不了就如实记为 `indirect`
//! （寄存器/内存操作数原样写出），绝不填一个像模像样的假目标。
//!
//! 产物：
//! - `text/call_edges.txt`  每行 `0xfrom <tab> from_name <tab> kind <tab> 0xto <tab> to_name`
//! - `callgraph.dot`        直接调用图（仅含本二进制内已命名目标，边数有上限）

use std::io::Write as _;
use crate::analyzer::{Analyzer, LibGroups};
use capstone::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
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
    let n_threads = crate::analyzer::n_threads();
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
                let cs = match crate::disasm::build_cs(is_arm64) {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = tx.send((pi, Vec::new(), Some(e)));
                        return;
                    }
                };
                let mut out: Vec<Edge> = Vec::new();
                for &(ep, payload, csize, ref fname) in &plan_ref[b..e] {
                    // 切片与边界（含防回绕）走共享基元；反汇编地址仍是 payload 而非文件偏移
                    let Some((_foff, code)) =
                        crate::disasm::function_code(data, slice_off, payload, csize)
                    else {
                        continue;
                    };
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
    // 先算总数再一次到位：`extend` 逐个分片追加会让这个 Vec 反复翻倍 realloc
    // （material_3_demo 上约 9.7 万条边，每条含两个 String）。
    let total: usize = parts.iter().flatten().map(|v| v.len()).sum();
    let mut edges: Vec<Edge> = Vec::with_capacity(total);
    for p in parts.into_iter().flatten() {
        edges.extend(p);
    }
    // `sort_by_key` **不缓存键**——每次比较都重新调一次闭包，所以原来那个
    // `a.to_text.clone()` 是「每次比较分配一个 String」：9.7 万条边 × O(log N)
    // ≈ 160 万次克隆，大应用上更多。改成借用比较，序完全相同
    // （`String` 与 `str` 都是逐字节字典序），`sort_by` 同样是稳定排序。
    edges.sort_by(|a, b| {
        (a.from, a.to, a.to_text.as_str()).cmp(&(b.from, b.to, b.to_text.as_str()))
    });
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
    let mut txt = crate::export::stream_writer(&text_dir, "call_edges.txt")?;
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
    crate::export::finish_writer(txt, "call_edges.txt")?;

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
    let mut dot = crate::export::stream_writer(out_dir, "callgraph.dot")?;
    let _ = writeln!(dot, "// dae call graph — direct calls (bl / call imm) between named functions");
    let _ = dot.write_all(b"digraph dae_callgraph {\n  rankdir=LR;\n  node [shape=box, fontsize=10];\n");
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
    let _ = dot.write_all(b"}\n");
    crate::export::finish_writer(dot, "callgraph.dot")?;

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


/// 从 stub 序言解出「被分配的类」→ 名字。
///
/// arm64 形如 `mov xD, #lo` + `movk xD, #hi, lsl #16`（汇编器拼 32 位常量的固定写法，
/// 目标寄存器必须同一个，且必须带 `lsl #16`——否则第二次写是覆盖而非拼接）；
/// x64 形如 `mov r8d, imm32` + `call ...`（tag 字直接用 32 位立即数装载）。
/// 解出的 cid 只有命中已知类名才返回名字，否则 None（**不猜**）。
/// stub 命名：解析 prologue 里物化的 class-id tag 字，得到它操作的**类**。
///
/// 两类 stub 的 prologue 是同一个形状（先物化 cid），区别在**之后**：
/// * `mov r8d, <tag>; jmp <分配器>`（arm64 `mov/movk; b`）——**立刻转移**，是分配 stub；
/// * `mov r8d, <tag>; je ..; cmp r8d, <运行期 cid>; jne <慢路径>`——**就地比较**，
///   是类型测试 stub（实测 x64 语料里 176 个 stub 有 88 个是这类，名字即被测类）。
///
/// 所以按「tag 物化之后是否立即无条件转移」分流，两条都只输出**解出来的**类名。
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
    let mnem = |i: usize| -> String {
        v.get(i)
            .and_then(|x| x.mnemonic())
            .map(|m| m.to_ascii_lowercase())
            .unwrap_or_default()
    };
    let ops = |i: usize| -> String {
        v.get(i).and_then(|x| x.op_str()).unwrap_or("").to_string()
    };
    // tag 物化可能在 0 或 1 号指令：类型测试 stub 前面先有一条守卫
    // （x64 `test al, 1`、arm64 `tbnz w0, #0, …`）——不跳过它就会整类漏掉。
    let start = if mnem(0) == "mov" {
        0
    } else if mnem(1) == "mov" {
        1
    } else {
        return None;
    };
    let (o0, o1) = (ops(start), ops(start + 1));
    let tag = if is_arm64 {
        if mnem(start + 1) != "movk" {
            return None;
        }
        let d0 = o0.split(',').next()?.trim();
        if o1.split(',').next()?.trim() != d0 || !o1.contains("lsl #16") {
            return None;
        }
        first_imm(&o0)? | (first_imm(&o1)? << 16)
    } else {
        // x64：tag 之后可以是 `jmp/call <分配器>`（thunk）或直接比较（类型测试）
        if !o0.contains("0x") && !o0.chars().any(|c| c.is_ascii_digit()) {
            return None;
        }
        first_imm(&o0)?
    };
    // 只认**分配 stub**：它的 prologue 把完整 tag 字物化出来（`mov r8d, 0x1e50204`），
    // 右移 cid_tag_pos 即类 id，且紧接着无条件转移到分配器。
    //
    // 类型测试 stub 看起来像同一个形状（先物化一个 cid 再比较），但它物化/比较的是**裸 cid**，
    // 而且前面的 `mov r8d, 0x31`（49 = `_Smi`）只是 Smi 分支的初值。按"第一个能对上类名的立即数"
    // 去猜会**编造**：实测 12 个候选里 4 个是错的（把 iso 分配桩 `AllocateMintShared*Stub`
    // 与 `AllocateContextStub` 命名成了类型测试，还有 1 个认成了 `_Smi`）。
    // 真值对拍直接抓出来了——所以这里退回"只命名能证明的"，类型测试 stub 留空
    // （正确做法是走对象池：Type 条目的 `type_test_stub_` 字段指向 stub，见 docs/COMPARISON）。
    let transfer = if is_arm64 {
        matches!(mnem(start + 2).as_str(), "b" | "br")
    } else {
        matches!(mnem(start + 1).as_str(), "jmp" | "call")
    };
    if !transfer {
        return None;
    }
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
    let Ok(cs) = crate::disasm::build_cs(is_arm64) else {
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
/// 形状解码：**调用约定转换包装**（save-all / restore-all）→ `RuntimeCallStub_0x…`。
///
/// 判据完全来自代码、可机械校验，不依赖任何版本相关的常量：
/// 1. 第 0 条把 `lr` 压栈（`str lr, [SP, #-8]!`）；
/// 2. 紧随 **≥6 组 `stp`** 把成对寄存器全部压栈（arm64 上是 r0..r5 / r6..r9 / r10..r13 /
///    r14,r19 / r20,CODE_REG / r24,r25 —— 即**全部**参数寄存器与固定寄存器）；
/// 3. 结尾 `ret` 之前有 **≥6 组 `ldp`**，且**第一组 stp 的寄存器对 == 最后一组 ldp 的寄存器对**
///    （严格逆序恢复）。
///
/// 没有任何普通 Dart 函数会保存并恢复全部参数寄存器与固定寄存器，所以这个形状唯一对应
/// 「转出到非 Dart 代码（VM runtime / native）」的包装。**它只声称到这一层**：
/// 具体是哪一个 runtime entry **不可证**——profile 的 `runtime_offsets` 只有 7 个键，
/// 不含这个形状里出现的 `THR+0x188` 与 `THR+0x488`，所以名字里保留地址而不猜 entry 名
/// （判据同撤回 `isSmi` 那次：一个形状对应多个语义时，命名就是编造）。
///
/// 实测 material_3_demo：这个形状有 **11 个地址 / 22 847 次调用 = 全部未命名调用的 53%**
/// （`0x3dc328`×12676、`0x3dc7b0`×5521 等）。42 759 个 `sub_0x…()` 调用点只有 346 个不同地址，
/// 89.8% 在 stub 表里。
fn runtime_stub_name(analyzer: &Analyzer, cs: &Capstone, addr: u64, is_arm64: bool) -> Option<String> {
    if !is_arm64 {
        return None; // x64 的对应形状（一串 push / pop）尚未取证，不猜
    }
    let foff = addr + analyzer.slice_off;
    let data = analyzer.data;
    if foff >= data.len() as u64 {
        return None;
    }
    // 窗口取 384 字节：实测这类 stub 是 128 字节，留足余量；越界部分自然截断
    let end = (foff + 384).min(data.len() as u64);
    let code = &data[foff as usize..end as usize];
    let insns = cs.disasm_all(code, addr).ok()?;
    let v: Vec<_> = insns.iter().collect();
    let mnem = |i: usize| -> String {
        v.get(i)
            .and_then(|x| x.mnemonic())
            .map(|m| m.to_ascii_lowercase())
            .unwrap_or_default()
    };
    let ops = |i: usize| -> String {
        v.get(i).and_then(|x| x.op_str()).unwrap_or("").to_string()
    };
    // 1) lr 压栈
    if mnem(0) != "str" {
        return None;
    }
    let o0 = ops(0);
    if !(o0.contains("lr") || o0.contains("x30")) || !o0.contains('[') {
        return None;
    }
    // 2) 紧随的连续 stp 组
    let mut stp: Vec<String> = Vec::new();
    let mut i = 1usize;
    while i < v.len() && mnem(i) == "stp" {
        stp.push(ops(i));
        i += 1;
    }
    if stp.len() < 6 {
        return None;
    }
    // 3) 找到 ret，再往回数连续的 ldp 组
    let ret_at = (1..v.len()).find(|&k| mnem(k) == "ret")?;
    let mut ldp: Vec<String> = Vec::new();
    let mut k = ret_at;
    // ret 之前允许最多 2 条非 ldp 指令（实测是 `add x15, x15, #8`，弹掉最初压的 lr）。
    // ⚠️ **不能按操作数里有没有 "sp" 来认这条 add**：Dart 的 arm64 栈指针在 Dart 代码里是
    // **x15**（SDK constants_arm64.h 的 `R15 = 15; // SP in Dart code.`），capstone 给出的
    // 操作数是 `x15, x15, #8`，里面根本没有 "sp" 字样——第一版就是这么写的，于是这条 add
    // 没被跳过、往回的 ldp 收集到 0 组，346 个地址一个都没匹配上。
    let mut skip = 0u8;
    while k > 0 && mnem(k - 1) != "ldp" && skip < 2 {
        k -= 1;
        skip += 1;
    }
    while k > 0 && mnem(k - 1) == "ldp" {
        k -= 1;
        ldp.push(ops(k));
    }
    if ldp.len() < 6 {
        return None;
    }
    // 镜像校验：第一组 stp 的寄存器对必须等于最后一组 ldp 的寄存器对
    // 只取 `[` 之前的寄存器部分：`x24, x25, [sp, #-0x10]!` → ["x24","x25"]。
    // ⚠️ 不能按 `]` 切——那样会把 `[sp, #-0x10` 也当成一个「寄存器」，镜像校验永远不成立
    // （第一版就是这么写的，346 个地址一个都没匹配上）。
    let regs = |o: &str| -> Vec<String> {
        o.split('[')
            .next()
            .unwrap_or("")
            .split(',')
            .map(|t| t.trim().to_ascii_lowercase())
            .filter(|t| !t.is_empty())
            .collect()
    };
    // `ldp` 是从 ret 往回数的，所以 ldp[0] 是**程序序最后**那一条，恰好与 stp[0] 配对
    // （入口第一组压栈 = 出口最后一组弹回）。第一版取了 ldp[len-1]（那是 `ldp fp, lr`），
    // 方向反了。
    let first_stp = regs(&stp[0]);
    let last_ldp = regs(&ldp[0]);
    if first_stp.len() < 2 || first_stp != last_ldp {
        return None;
    }
    Some(format!("RuntimeCallStub_{addr:#x}"))
}

pub fn alloc_stubs_at(analyzer: &Analyzer, addrs: &[u64]) -> Vec<(u64, Option<String>)> {
    let is_arm64 = analyzer.platform.arch == "arm64";
    if !class_layer_usable(analyzer) {
        return addrs.iter().map(|a| (*a, None)).collect();
    }
    let Ok(cs) = crate::disasm::build_cs(is_arm64) else {
        return addrs.iter().map(|a| (*a, None)).collect();
    };
    addrs
        .iter()
        .map(|a| {
            (
                *a,
                // 先试分配 stub（序言里的 class-id tag 字），认不出再试调用约定转换包装的形状
                alloc_stub_name(analyzer, &cs, *a, is_arm64)
                    .or_else(|| runtime_stub_name(analyzer, &cs, *a, is_arm64)),
            )
        })
        .collect()
}
