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

    let edges = collect_edges(analyzer, libs);

    // ---- 分配 stub 命名 ----
    // 直接目标里相当一部分是「每类分配 stub」：它们没有 Function 包装，因此不在
    // 导出名表里。但 stub 序言会把类 id 的 tag 字写进寄存器，可以就地解出来再
    // 映射到类名——只有 cid 命中已知类名时才命名，否则留空（不猜）。
    let stub_names = name_alloc_stubs(analyzer, &edges, &name_of);
    // stub 名字优先：name_of 对这些地址给的只是 `sub_0x…` 占位，
    // 而真函数名不会进 stub_names（它们被上面的 `Some(n) if n != placeholder` 挡在 targets 之外）。
    let resolve = |to: u64| -> &str {
        if let Some(s) = stub_names.get(&to) {
            return s.as_str();
        }
        name_of.get(&to).map(|s| s.as_str()).unwrap_or("")
    };

    // ---- text/call_edges.txt ----
    let mut txt = crate::export::stream_writer(&text_dir, "call_edges.txt")?;
    let (mut n_direct, mut n_indirect, mut n_resolved) = (0usize, 0usize, 0usize);
    for e in &edges {
        match e.kind {
            "direct" => {
                let to = e.to.unwrap_or(0);
                let to_name = resolve(to);
                // ⚠️ 「非空」不等于「解出了真名字」：`name_map` 给**每个**指令表入口都兜了
                // `sub_{ep:#x}` 占位，所以按非空数会得到 94.7% 这种虚高值
                // （与 decompiler 的 calls_named 同一个坑，那边在 7ea269a 已修，这边漏了）。
                if !to_name.is_empty() && !to_name.starts_with("sub_0x") {
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
/// 一个地址上的**一次**反汇编，供全部命名器共用。
///
/// ⚠️ 这是性能关键：`alloc_stubs_at` 会对**每一个**未被 Function 引用的表项依次试 5 个命名器，
/// 而原先**每个命名器各自反汇编自己的窗口**（24 / 384 / 32 / ≤4096 / ≤4096 字节），
/// 于是同一段字节最多被解码 5 次、合计约 238 条指令。实测 `names+stubs` 阶段因此占
/// 飞书全量导出的 **3.43 s / 7.7 s（45%）**、Reqable 的 **2.68 s / 6.6 s（41%）**。
/// 改成每地址只解码一次（窗口取所在表项的剩余字节、上限 4 KiB，最多 96 条指令）后
/// 约 2.5× 少于原来的解码量。
///
/// 96 条对所有已取证的形状都够：`runtime_stub_name` 的 save-all + 镜像恢复实测 32 条、
/// 其旧窗口 384 字节在 arm64 上也正好是 96 条；x64 指令更短，96 条覆盖的字节更多。
/// 取不到的失败模式是「不命名」，**绝不会是「命名错」**。
pub(crate) fn disasm_stub<'a>(
    analyzer: &Analyzer,
    cs: &'a Capstone,
    addr: u64,
    idx: &StubIdx,
) -> Option<capstone::Instructions<'a>> {
    let foff = addr.checked_add(analyzer.slice_off)?;
    if foff >= analyzer.data.len() as u64 {
        return None;
    }
    let win = idx.remaining(addr).unwrap_or(384).clamp(32, 4096);
    let end = (foff + win).min(analyzer.data.len() as u64);
    cs.disasm_count(&analyzer.data[foff as usize..end as usize], addr, 96).ok()
}

/// 命名器共用的小工具：取第 i 条的助记符（小写）与操作数文本。
#[inline]
fn mn_at(ins: &capstone::Instructions, i: usize) -> String {
    ins.get(i).and_then(|x| x.mnemonic()).map(|m| m.to_ascii_lowercase()).unwrap_or_default()
}
#[inline]
fn ops_at(ins: &capstone::Instructions, i: usize) -> String {
    ins.get(i).and_then(|x| x.op_str()).unwrap_or("").to_string()
}

fn alloc_stub_name(
    ins: &capstone::Instructions,
    analyzer: &Analyzer,
    is_arm64: bool,
) -> Option<String> {
    let mnem = |i: usize| mn_at(ins, i);
    let ops = |i: usize| ops_at(ins, i);
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
) -> BTreeMap<u64, String> {
    let mut targets: BTreeSet<u64> = BTreeSet::new();
    for e in edges {
        if e.kind != "direct" {
            continue;
        }
        let Some(t) = e.to else { continue };
        // ⚠️ `name_map` 给**每个指令表入口**都兜了一个 `sub_{ep:#x}` 占位，
        // 所以「不在 name_of 里」并不等于「没有名字可解」。上一轮加 `RuntimeCallStub`
        // 时就是被这个占位挡住：`dart/` 与 `text/stubs.txt` 有名字，
        // 而 `text/call_edges.txt` 里同一个地址仍是 `sub_0x…`（material_3_demo 14 000 处）。
        // 判据是「name_of 给的就是占位本身」，此时照样送去命名。
        let placeholder = format!("sub_{t:#x}");
        match name_of.get(&t) {
            Some(n) if n != &placeholder => {}
            _ => {
                targets.insert(t);
            }
        }
    }
    let mut out = BTreeMap::new();
    // 「一个表项里的多个子 stub」（写屏障族）：目标是条目**内部**地址，
    // 不在任何按表项遍历的集合里，必须单独枚举。
    out.extend(write_barrier_sub_stubs(analyzer));
    if targets.is_empty() || !class_layer_usable(analyzer) {
        return out;
    }
    // ⚠️ 这里必须走 `alloc_stubs_at`（完整命名链），不能再自己只调 `alloc_stub_name`：
    // 上一轮加 `RuntimeCallStub` 时只把链接进了 `alloc_stubs_at`，而本函数另有一份
    // 只调分配 stub 的循环 ⇒ `dart/` 与 `text/stubs.txt` 有名字、`text/call_edges.txt`
    // 里同一个地址却是空的（material_3_demo 实测 4569 行第 5 列为空）。
    // 两条路径分叉就是这类「一半产物有、一半没有」的来源，统一成一个入口。
    let tv: Vec<u64> = targets.into_iter().collect();
    for (a, n) in alloc_stubs_at(analyzer, &tv) {
        if let Some(n) = n {
            out.entry(a).or_insert(n);
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
/// 「转出到非 Dart 代码（VM runtime / native）」的包装。
///
/// ⚠️ **本函数原来的注释断言「具体是哪一个 runtime entry 不可证」，那是错的**（理由是
/// `runtime_offsets` 只有 7 个键——查错了表）。`struct_tables::dart_thread` 里那份 per-version
/// `DartThread` 布局**484 个字段全有名字**：dart 3.13.0 的 `THR+0x188` 就是
/// `stack_overflow_shared_without_fpu_regs_stub`。所以 entry 名是可证的，本名字只是**说少了**
/// （不错，但不够具体）。**这一层已由 `code_reg_stub_name` 实现**：身份级的可证命名，
/// 且它排在本函数之前，所以本函数现在只兜「本体里没有 CODE_REG 装载」的那些。
/// ⚠️ 早先这里记的「340 个未命名地址里 338 个可命名、占直接调用 32.4%」是**错的**（大约高了一倍）：
/// 那次扫描读的是整个**指令表条目**的反汇编，而一个条目可能装多个 stub，于是把**邻居**的
/// `ldr` 记到了当前地址头上。按「截到第一条终止指令」重测是 **102/340 个地址、
/// 14 496 次调用＝直接调用的 16.7%**（其中 CODE_REG 身份层 11 个地址/11 318 次，已实现；
/// 唯一 `*_entry_point` 层 91 个地址/3 178 次，未实现，见 docs/DECOMPILER.md 的 backlog）。
///
/// 另：通不过下面镜像校验的那些地址不是谜——它们序言相同但**以 `brk #0` 结尾**（调用 runtime
/// 后不返回，因此没有「恢复」可镜像），例如 `0x3dc7b0`（5 730 次调用）加载
/// `null_cast_error_shared_without_fpu_regs_stub` + `NullCastError_entry_point`。
/// 用镜像判据拒绝它们是对的，只是镜像不是这一族里唯一可证的判据。
///
/// 实测 material_3_demo：这个形状有 **11 个地址 / 22 847 次调用 = 全部未命名调用的 53%**
/// （`0x3dc328`×12676、`0x3dc7b0`×5521 等）。42 759 个 `sub_0x…()` 调用点只有 346 个不同地址，
/// 89.8% 在 stub 表里。
fn runtime_stub_name(ins: &capstone::Instructions, addr: u64, is_arm64: bool) -> Option<String> {
    if !is_arm64 {
        return None; // x64 的对应形状（一串 push / pop）尚未取证，不猜
    }
    let mnem = |i: usize| mn_at(ins, i);
    let ops = |i: usize| ops_at(ins, i);
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
    while i < ins.len() && mnem(i) == "stp" {
        stp.push(ops(i));
        i += 1;
    }
    if stp.len() < 6 {
        return None;
    }
    // 3) 找到 ret，再往回数连续的 ldp 组
    let ret_at = (1..ins.len()).find(|&k| mnem(k) == "ret")?;
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


/// DartThread 布局表：把 `struct_tables::dart_thread(abi, arch)` 的头文件解析成
/// 「字段序号 → 字段名」，于是 **offset = 序号 × 8** 就能查到线程字段名。
///
/// 这与 r2/IDA 结构头用的是**同一份** per-version 精确布局，不引入第二套常量。
/// 换算的正确性是实测出来的、不是假设的：48 份头文件（24 版 × arm64/x64）
/// **每一行都是 `__int64 <name>;`**（没有第二种类型、没有一行解析失败），
/// 且与 `profiles/struct/*/dart_struct_fields-*.json` 里带**显式 offset** 的表逐字段对过账
/// （约 1.4 万次比对，**0 处不一致**）。
/// ⚠️ `compressed` 必须传**目标产物**的真实取值，否则会整段错位 8 字节。
///
/// SDK `runtime/vm/thread.h` 里 `heap_base_` 是**条件字段**：
/// ```text
/// volatile RelaxedAtomic<uword> stack_limit_;
/// uword                         write_barrier_mask_;
/// #if defined(DART_COMPRESSED_POINTERS)
/// uword                         heap_base_;      ← 只有压缩指针构建才有
/// #endif
/// uword                         top_;
/// uword                         end_;
/// ```
/// 而且它是 `Thread` 里**唯一**一个 `DART_COMPRESSED_POINTERS` 条件字段
/// （3.3.4 与 3.13.0 的 thread.h 各只有 3 处该宏，另两处是访问器方法、不是字段声明）。
/// 所以压缩指针构建里，`write_barrier_mask_` 之后的**每一个**字段都比非压缩布局晚 8 字节。
///
/// 仓库里的 48 份头文件对此**不一致**：2.13.4–2.19.6 的 7 个版本已经含 `heap_base`，
/// 其余（含 3.3.4 / 3.6.1 / 3.13.0）不含。所以规则是「目标压缩 且 头里没有」才插一个。
///
/// 两端都有实测对账：
/// * weibo（dart **2.19.6**、压缩指针，头里**已有** `heap_base`@0x48）：其 640 字节屏障表
///   `0x8e5c38` 装载 `[x26, #0x248]`，index 73 在头里正是 `write_barrier_entry_point` ✓
/// * Reqable（dart **3.3.4**、压缩指针，头里**没有** `heap_base`）：分配器 bump 在
///   `[x26, #0x50]`，而不插 `heap_base` 时头说 `top`=0x48、`end`=0x50 ⇒ 差 8 字节。
///   插入后 `top`=0x50 ✓，且屏障装载 `#0x1e8` 由 index 61（`array_write_barrier_entry_point`）
///   纠正为 index 60（**`write_barrier_entry_point`**）。
///   ⚠️ 也就是说**在修好这一条之前，dae 对 Reqable/飞书发布的 `ArrayWriteBarrierStub_*` 是错的**，
///   真名是 `WriteBarrierStub_*`；material_3_demo（3.13.0、**非**压缩）一直是对的。
fn thread_field_names(abi: &str, arch: &str, compressed: bool) -> Vec<String> {
    let Some(hdr) = crate::struct_tables::dart_thread(abi, arch) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for ln in hdr.lines().skip(1) {
        let s = ln.trim();
        if s.starts_with('}') {
            break;
        }
        // `__int64 write_barrier_entry_point;` → 取分号前最后一个词
        let body = s.trim_end_matches(';').trim();
        if let Some(name) = body.split_whitespace().last() {
            out.push(name.to_string());
        }
    }
    if compressed && !out.iter().any(|n| n == "heap_base") {
        if let Some(i) = out.iter().position(|n| n == "write_barrier_mask") {
            out.insert(i + 1, "heap_base".to_string());
        }
    }
    out
}

/// `snake_case` → `CamelCase`（只用于把 profile 自己的字段名换个写法，不增删语素）。
fn camel(snake: &str) -> String {
    let mut s = String::with_capacity(snake.len());
    let mut up = true;
    for c in snake.chars() {
        if c == '_' {
            up = true;
        } else if up {
            s.extend(c.to_uppercase());
            up = false;
        } else {
            s.push(c);
        }
    }
    s
}

/// 写屏障子 stub 的名字，全部来自**可机械校验的形状 + profile 自己的字段名**。
///
/// ## 为什么需要它
///
/// 一个指令表条目里可能装着**多个**子 stub。material_3_demo 的 `0x3e0a84` 表项长度 640 字节，
/// 实际是 **20 个 32 字节的子 stub**；调用方直接 `bl` 到 `0x3e0aa4`（表项 +0x20）这类**内部地址**，
/// 于是这些目标既不在函数表、也不在 stub 表里。实测 material_3_demo 有 **10 个这样的地址 /
/// 4569 次调用（占全部直接调用 5.3%）**，全部落在这一个表项内、间隔恰好 0x20。
///
/// ## 判据（逐条可校验，两份语料 × 两个 SDK 版本 × 两种容器实测形状完全一致）
///
/// 32 字节 = 8 条指令，助记符序列必须**恰好**是
/// `str, str, mov, ldr, blr, ldr, ldr, ret`，且：
/// 1. 两条 `str` 分别把 LR 与 x1 压栈（pre-index）；
/// 2. `mov` 的目的必须是 x1，源寄存器就是本变体的**唯一区别**；
/// 3. `ldr` 的目的必须是 LR、基址必须是 **THR**、位移必须是 8 的倍数；
/// 4. `blr` 跳到那个 LR；
/// 5. 两条 `ldr` 以**严格逆序**弹回 x1 与 LR（与 1 镜像）；
/// 6. 结尾 `ret`。
///
/// ## 名字只声称可证的部分
///
/// 位移**不写死**：material_3_demo（dart 3.13.0）是 `#0x1f8`，而 Reqable（dart 3.3.4）是
/// **`#0x1e8`** —— 把 0x1f8 硬编码会让 Reqable 的名字变成编造。做法是**从指令里读出位移**，
/// 再拿该版本的 DartThread 布局查字段名，并要求它以 `_entry_point` 结尾：
/// 3.13.0 的 0x1f8 → `write_barrier_entry_point` → `WriteBarrierStub_x0`；
/// 3.3.4 的 0x1e8 → `array_write_barrier_entry_point` → **`ArrayWriteBarrierStub_x0`**。
/// 两个是**不同的**屏障，profile 自己就这么区分，所以名字也跟着区分。
/// 字段名不以 `_entry_point` 结尾、或位移不在表内、或形状有一条不合，就**不命名**（返回 None），
/// 绝不退化成猜。后缀用**物理寄存器名**（`x0`..`x25`）而不是渲染后的别名，避免歧义。
///
/// 变体的源寄存器实测是 x0–x14、x19、x20、x23、x24、x25——恰好跳过了 Dart arm64 里
/// 有固定职责的那些（x15=SP、x16/x17=scratch、x18=platform、x21/x22、x26=THR、x27=PP、
/// x29=FP、x30=LR）。这只是旁证，命名不依赖它。
pub(crate) fn write_barrier_stub_name(
    ins: &capstone::Instructions,
    is_arm64: bool,
    rl: &crate::export::asm::Roles,
    fields: &[String],
) -> Option<String> {
    if !is_arm64 {
        return None; // x64 的对应形状尚未取证，不猜
    }
    // 一个子 stub 恰好 8 条指令 = 32 字节。原来只解 32 字节并要求 `v.len() == 8`；
    // 共用窗口后指令更多，等价判据是「至少 8 条，且只看前 8 条」——arm64 定长 4 字节，
    // 前 8 条就是那 32 字节，两种写法完全等价。
    if ins.len() < 8 {
        return None;
    }
    let mn = |i: usize| mn_at(ins, i);
    let ops = |i: usize| ops_at(ins, i);
    const WANT: [&str; 8] = ["str", "str", "mov", "ldr", "blr", "ldr", "ldr", "ret"];
    for (i, w) in WANT.iter().enumerate() {
        if mn(i) != *w {
            return None;
        }
    }
    // 操作数按 `,` 切成「寄存器段」与「内存段」；内存段以 `[` 开头。
    // ⚠️ 不能用 contains(寄存器名) 判断：`x1` 是 `x15`/`x16` 的子串（本项目踩过 `x27`⊂`0x27`）。
    let parts = |i: usize| -> Vec<String> {
        ops(i).split(',').map(|s| s.trim().to_ascii_lowercase()).collect()
    };
    let dst = |i: usize| -> String { parts(i).into_iter().next().unwrap_or_default() };
    // 内存段里的基址寄存器：`[x15` / `[x26`
    let base = |i: usize| -> String {
        ops(i)
            .split('[')
            .nth(1)
            .unwrap_or("")
            .split(|c: char| !c.is_ascii_alphanumeric())
            .next()
            .unwrap_or("")
            .to_ascii_lowercase()
    };
    let imm = |i: usize| -> Option<u64> {
        let o = ops(i);
        let seg = o.split('[').nth(1)?;
        let h = seg.split('#').nth(1)?;
        let h = h.trim().trim_end_matches(']').trim();
        let (h, neg) = h.strip_prefix('-').map(|x| (x, true)).unwrap_or((h, false));
        let h = h.strip_prefix("0x").unwrap_or(h);
        let n = u64::from_str_radix(h, 16).ok()?;
        Some(if neg { n.wrapping_neg() } else { n })
    };
    // 压栈是 pre-index（`]!`）、弹回是 post-index（`], #`）——两者都查，
    // 因为「先压 LR 再压 x1、先弹 x1 再弹 LR」的**顺序**才是这个形状的实质。
    let is_pre = |i: usize| ops(i).contains("]!");
    let is_post = |i: usize| ops(i).contains("], #");
    // 1) 两条 str：LR 与 x1 压栈（pre-index）
    if dst(0) != rl.lr || dst(1) != "x1" || !is_pre(0) || !is_pre(1) {
        return None;
    }
    if base(0) != rl.sp || base(1) != rl.sp {
        return None;
    }
    // 2) mov 的目的必须是 x1，源就是本变体的区别所在
    if dst(2) != "x1" {
        return None;
    }
    let src = parts(2).get(1).cloned().unwrap_or_default();
    // ⚠️ 不能排除 `mov x1, x1`（源==目的）。它确实是 20 个变体之一：值本来就在 x1，
    // 所以这条 mov 是空操作，但**这个入口的语义仍然是「转发 x1」**，是可证的。
    // 第一版把 `src == "x1"` 当可疑排除了，后果不只是少一个名字：
    // `write_barrier_sub_stubs` 要求**整条目每一块都通过**，于是这一个变体
    // 把整个 640 字节表项判成「不是子 stub 数组」，20 个名字一个都出不来。
    if !src.starts_with('x') {
        return None;
    }
    // 3) ldr：目的 LR、基址 THR、位移是 8 的倍数
    if dst(3) != rl.lr || base(3) != rl.thr {
        return None;
    }
    let off = imm(3)?;
    if off % 8 != 0 {
        return None;
    }
    // 4) blr 到那个 LR
    if dst(4) != rl.lr {
        return None;
    }
    // 5) 严格逆序弹回（与 1 镜像）：先 x1 再 LR，都是 post-index
    if dst(5) != "x1" || dst(6) != rl.lr || !is_post(5) || !is_post(6) {
        return None;
    }
    if base(5) != rl.sp || base(6) != rl.sp {
        return None;
    }
    // 6) 字段名必须来自该版本的 DartThread 布局，且是 *_entry_point
    let name = fields.get((off / 8) as usize)?;
    let stem = name.strip_suffix("_entry_point")?;
    if stem.is_empty() {
        return None;
    }
    Some(format!("{}Stub_{src}", camel(stem)))
}


/// 内联（「胖」）分配 stub 的名字：本体自己做完 bump 分配，而不是跳去共享分配器的瘦 shim。
///
/// `alloc_stub_name` 认的是 12 字节瘦 shim（`mov`+`movk` 物化 tag 后**立即** `b`/`br`），
/// 例如 `0x4294` → `AllocationStub_Duration`。但 Dart 还会把整段分配器**内联**成胖 stub，
/// material_3_demo 上有 **13 个 / 7 275 次调用（占全部直接调用 8.4%）**，此前一个都没名字。
///
/// ## 判据（十条，全部机械可校验；实测 13/13 通过、0 个误纳）
///
/// ```text
/// ldp  <A>, <B>, [THR, #<top>]      ; 一次取 bump 指针 top 与上限 end
/// add  <A>, <A>, #<size>            ; 大小必须是**定长立即数**
/// cmp  <B>, <A>
/// b.ls <慢路径>                      ; 放不下就走慢路径
/// str  <A>, [THR, #<top>]           ; 提交 bump（写回**同一个** top 字段）
/// sub  <A>, <A>, #<size-1>          ; 退回 tagged 指针——必须恰好是 size-1
/// mov  <H>, #<lo>
/// movk <H>, #<hi>, lsl #16          ; 物化对象头
/// stur <H>, [<obj>, #-1]            ; 头字存在 payload 前一个字（tagged 布局）
/// ```
///
/// `top` 的位移**不写死**：从该版本的 `DartThread` 布局里按**字段名**反查
/// （3.13.0 是 0x58，别的版本会搬家——与写屏障那条同一个教训）。
/// 类 id 用 profile 的 `tagging.cid_tag_pos`/`cid_tag_mask` 从对象头里取，
/// 类名先查快照的 `cname_by_cid`、再退回 profile 的 `class_id_names`（预设类）。
///
/// ## 为什么「定长立即数」这一条是防编造的关键
///
/// 变长分配器（`AllocateArray`/`AllocateTypedData` 一类）的大小来自**寄存器**
/// （`add x2, x2, x1, lsl #3`），而它们本体里的 `mov x17, #0xfffa` 是**长度上界**、
/// 不是对象头。按「第一个 `mov` + 第一个 `movk`」配对会在 `0x3df2a0`/`0x3e057c` 上
/// 解出 cid 16（WeakSerializationReference）与 95（TwoByteString）——**两个都是编造**。
/// 要求 `add <A>, <A>, #<imm>` 是定长立即数、且紧跟 `stur <H>, [<obj>, #-1]` 存头，
/// 这两类就自然被挡在门外（实测候选集里根本没进来）。
///
/// ## 解出来的类名有独立旁证
///
/// 13 个全部落在语义自洽的类上，且**大小与类相符**：`Mint`/`Double` 都是 0x10
/// （头 + 一个值）、`Closure` 0x30 与 0x40、`Record` 0x20 与 0x30（Dart 3 record 按元数不同）、
/// `GrowableObjectArray` 0x20、`Float64x2`/`Float32x4`/`Int32x4` 都是 0x20。
/// 另外 `Closure` 那个胖 stub 的慢路径调的正是 `AllocateClosure_entry_point`、
/// `Double` 那个调 `AllocateDouble_entry_point`——**两条独立来源互相印证**。
///
/// 名字沿用既有约定 `AllocationStub_<Class>`（不带地址）：同一类可以有多个特化
/// （实测 `Mint`/`Closure` 各 2 个、`Record` 3 个），而现有的瘦 shim 也早就有重名
/// （1 858 个名字里 1 839 个不同，`AllocationStub__RenderInputPadding` 出现 3 次），
/// 所以重名不是新问题，且「两个特化都在分配同一个类」在语义上是对的。
pub(crate) fn inline_alloc_stub_name(
    ins: &capstone::Instructions,
    analyzer: &Analyzer,
    is_arm64: bool,
    rl: &crate::export::asm::Roles,
    fields: &[String],
) -> Option<String> {
    if !is_arm64 {
        return None; // x64 的物化形态不同（单条 mov imm32），未取证，不猜
    }
    // 先用一条指令廉价 bail（本形状的第 0 条必是 `ldp`），再建小表：
    // 建表要分配 String，不该为「一看就不像」的地址付这个钱。
    if mn_at(ins, 0) != "ldp" {
        return None;
    }
    let n_take = ins.len().min(24);
    let v: Vec<(String, String)> = (0..n_take).map(|i| (mn_at(ins, i), ops_at(ins, i))).collect();
    if v.len() < 9 {
        return None;
    }
    // 拆操作数：寄存器段 + 内存段（内存段以 `[` 开头）
    let parts = |i: usize| -> Vec<String> {
        v[i].1.split(',').map(|s| s.trim().to_ascii_lowercase()).collect()
    };
    let base_off = |i: usize| -> Option<(String, u64)> {
        let seg = v[i].1.split('[').nth(1)?;
        let mut it = seg.split(',');
        let b = it.next()?.trim().trim_end_matches(']').to_ascii_lowercase();
        let imm = it.next().unwrap_or("").trim().trim_end_matches(']');
        let imm = imm.trim().strip_prefix('#').unwrap_or(imm.trim());
        Some((b, parse_imm(imm).ok()?))
    };
    // `top` 字段的位移按**名字**反查该版本布局（不写死 0x58）
    let top_off = (fields.iter().position(|f| f == "top")? as u64) * 8;

    // 1) ldp A, B, [THR, #top]
    if v[0].0 != "ldp" {
        return None;
    }
    let p0 = parts(0);
    if p0.len() < 2 {
        return None;
    }
    let (ba, oa) = base_off(0)?;
    if !ba.eq_ignore_ascii_case(&rl.thr) || oa != top_off {
        return None;
    }
    let (ra, rb) = (p0[0].clone(), p0[1].clone());
    // 2) add A, A, #size（定长立即数）
    if v[1].0 != "add" {
        return None;
    }
    let p1 = parts(1);
    if p1.len() != 3 || p1[0] != ra || p1[1] != ra || !p1[2].starts_with('#') {
        return None;
    }
    let size = parse_imm(p1[2].trim_start_matches('#')).ok()?;
    // 下界用 profile 的 `object_alignment`（对象至少一格），不写死 16；
    // 上界是纯粹的合理性上限，取不到的失败模式是「不命名」而不是「命名错」。
    let align = analyzer.profile.tagging.object_alignment.max(1);
    if !(align..=0x10000).contains(&size) || size % align != 0 {
        return None;
    }
    // 3) cmp B, A  4) b.ls <慢路径>
    if v[2].0 != "cmp" {
        return None;
    }
    let p2 = parts(2);
    if p2.len() != 2 || p2[0] != rb || p2[1] != ra {
        return None;
    }
    if v[3].0 != "b.ls" {
        return None;
    }
    // 5) str A, [THR, #top]（提交 bump，写回同一字段）
    if v[4].0 != "str" {
        return None;
    }
    let p4 = parts(4);
    if p4.is_empty() || p4[0] != ra {
        return None;
    }
    let (b4, o4) = base_off(4)?;
    if !b4.eq_ignore_ascii_case(&rl.thr) || o4 != top_off {
        return None;
    }
    // 6) sub A, A, #(size-1)：tagged 指针回退必须恰好是 size-1
    if v[5].0 != "sub" {
        return None;
    }
    let p5 = parts(5);
    if p5.len() != 3 || p5[0] != ra || p5[1] != ra {
        return None;
    }
    if parse_imm(p5[2].trim().trim_start_matches('#')).ok()? != size - 1 {
        return None;
    }
    // 7..9) mov H,#lo ; movk H,#hi,lsl #16 ; stur H,[obj,#-1]
    if v[6].0 != "mov" || v[7].0 != "movk" {
        return None;
    }
    let p6 = parts(6);
    let p7 = parts(7);
    if p6.len() != 2 || p7.len() != 3 || p7[0] != p6[0] {
        return None;
    }
    if !p7[2].contains("lsl #16") {
        return None;
    }
    let hreg = p6[0].clone();
    let lo = parse_imm(p6[1].trim().trim_start_matches('#')).ok()?;
    let hi = parse_imm(p7[1].trim().trim_start_matches('#')).ok()?;
    if v[8].0 != "stur" {
        return None;
    }
    let p8 = parts(8);
    if p8.is_empty() || p8[0] != hreg {
        return None;
    }
    let seg8 = v[8].1.split('[').nth(1)?;
    if !seg8.contains("#-1") {
        return None; // 头字必须存在 payload 前一个字
    }
    // 类 id → 类名（快照优先，退回 profile 的预设类表）
    let hdr = lo | (hi << 16);
    let tg = &analyzer.profile.tagging;
    let cid = ((hdr >> tg.cid_tag_pos) & tg.cid_tag_mask) as i64;
    let name = analyzer
        .cname_by_cid
        .get(&cid)
        .cloned()
        .or_else(|| analyzer.profile.class_id_names.get(&cid.to_string()).cloned())?;
    if name.is_empty() || name == "?" || !name.chars().any(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(format!("AllocationStub_{name}"))
}


/// 由「本 stub 往 CODE_REG 里装的是哪个线程字段」命名——**身份级**的可证命名。
///
/// ## 判据
///
/// Dart 的 shared stub 在自己的序言里把**自己的 Code 对象**装进 CODE_REG
/// （`ldr x24, [THR, #<某个 *_stub 字段>]`）。所以：
/// 1. 从目标地址起反汇编，**遇到第一条终止指令（`ret`/`brk`/`br`/无条件 `b`）就停**；
/// 2. 在这段**本体**里找 `ldr <code_reg>, [THR, #imm]`；
/// 3. `imm` 必须 8 对齐、且在该版本 `DartThread` 布局里查到的字段名以 `_stub` 结尾；
/// 4. 名字 = 该字段名的 CamelCase + `_0x<addr>`（带地址，因为同一个字段可能被
///    多个地址装载：实测 `slow_type_test_stub` 有 2 个）。
///
/// ## ⚠️ 第 1 步的截断不是可选的
///
/// 一个指令表条目里可能装着**多个** stub（见 `write_barrier_sub_stubs`：640 字节 = 20 个变体；
/// 也有「胖分配 stub + 邻居 runtime 包装」共用一个条目的情况）。不截断就会把**邻居的指令**
/// 算到本地址头上。这不是理论风险：截断前 `allocate_mint_without_fpu_regs_stub`
/// 会被归给 `0x3df74c`，而 `0x3df74c` 的本体其实是 bump 分配（`ldp top/end` → `dmb` → `ret`）、
/// 那条 CODE_REG 装载属于同条目里的下一个 stub。截断后 13 个候选掉到 **11 个**，
/// 掉掉的正是两个假归属。（与「raw 反汇编注释块越过函数边界」是同一类错误。）
///
/// ## 刻意不做的一层
///
/// 本体里唯一一条 `ldr rN,[THR,#<*_entry_point>]` 也能解出名字（截断后 91 个地址 / 3178 次调用，
/// 如 `Throw_entry_point`、`Instanceof_entry_point`），但那是「**调用**某个 runtime entry」，
/// 不等于「**就是**那个 stub」；而 `allocate_object_slow_entry_point` 被 **80 个不同地址**装载
/// ——80 个分配 stub 共用一个慢路径，它们显然都不是「AllocateObjectSlow stub」。
/// 要做这层必须先定「同一字段只被一个地址装载才认身份」，本轮不做，见 docs 的 backlog。
pub(crate) fn code_reg_stub_name(
    ins: &capstone::Instructions,
    addr: u64,
    is_arm64: bool,
    rl: &crate::export::asm::Roles,
    fields: &[String],
) -> Option<String> {
    if !is_arm64 || fields.is_empty() {
        return None; // x64 的对应形状尚未取证，不猜
    }
    // 窗口与解码条数由 `disasm_stub` 统一决定（见其文档）：本体在第一条终止指令就结束，
    // 所以这里遇到终止指令立刻返回，多解出来的部分不会被看。
    for one in ins.iter() {
        let m = one.mnemonic().unwrap_or("").to_ascii_lowercase();
        let o = one.op_str().unwrap_or("");
        if m == "ldr" {
            // 只认 `ldr <code_reg>, [THR, #imm]`
            let mut it = o.split(',');
            let dst = it.next().unwrap_or("").trim();
            let rest = it.collect::<Vec<_>>().join(",").trim().to_string();
            if dst.eq_ignore_ascii_case(&rl.code_reg) {
                if let Some(seg) = rest.strip_prefix('[') {
                    let mut segit = seg.split(',');
                    let base = segit.next().unwrap_or("").trim();
                    if base.eq_ignore_ascii_case(&rl.thr) {
                        let imm = segit.next().unwrap_or("").trim().trim_end_matches(']');
                        let imm = imm.trim().strip_prefix('#').unwrap_or(imm.trim());
                        if let Ok(off) = parse_imm(imm) {
                            if off % 8 == 0 {
                                if let Some(name) = fields.get((off / 8) as usize) {
                                    if let Some(stem) = name.strip_suffix("_stub") {
                                        if !stem.is_empty() {
                                            // 字段名本身就以 `_stub` 结尾，CamelCase 后已经是
                                            // `…Stub`，所以**不再追加** `Stub`（第一版追加了，
                                            // 产出 `StackOverflowSharedWithoutFpuRegsStubStub_0x…`）。
                                            return Some(format!("{}_{addr:#x}", camel(name)));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // 本体到此为止：终止指令之后的字节属于**同条目里的下一个 stub**
        if matches!(m.as_str(), "ret" | "brk" | "br" | "b") {
            return None;
        }
    }
    None
}

/// 立即数解析：支持 `0x1f8` 与十进制，带负号。
fn parse_imm(s: &str) -> Result<u64, ()> {
    let s = s.trim();
    let (s, neg) = s.strip_prefix('-').map(|x| (x, true)).unwrap_or((s, false));
    let v = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).map_err(|_| ())?
    } else {
        s.parse::<u64>().map_err(|_| ())?
    };
    Ok(if neg { v.wrapping_neg() } else { v })
}

/// 「未被 Code 对象认领」的指令表条目，按入口地址升序。
///
/// ⚠️ **必须是预建索引，不能每次现扫**。第一版 `stub_entry_size` 对**每个候选地址**
/// 都从头扫一遍 `pc_offsets`，于是整体是 O(表项数 × 地址数)：飞书 59 772 个 stub ×
/// 79 327 条表项 ≈ **47 亿次**迭代，导出从 4.8 s 变成 **119.6 s（24.8×）**、
/// Reqable 4.8 s → 54.3 s（11.3×）、material_3_demo 0.87 s → 1.33 s。
/// 建一次索引 + 每地址二分是 O(n + m log n)，实测回到原来的量级。
/// 表项按 `pc_offsets` 升序遍历即可得到有序数组（`pc_offsets` 非递减，8 份语料实测）。
pub(crate) struct StubIdx {
    eps: Vec<u64>,
    ends: Vec<u64>,
}

impl StubIdx {
    fn build(analyzer: &Analyzer) -> Self {
        let claimed: BTreeSet<usize> = analyzer.func_eps.values().map(|(_, idx)| *idx).collect();
        let (mut eps, mut ends) = (Vec::new(), Vec::new());
        for idx in 0..analyzer.pc_offsets.len() {
            if claimed.contains(&idx) {
                continue;
            }
            if let Some((ep, size)) = analyzer.code_range(idx) {
                if let Some(end) = ep.checked_add(size) {
                    eps.push(ep);
                    ends.push(end);
                }
            }
        }
        StubIdx { eps, ends }
    }

    /// 地址所在条目里、从该地址起还剩多少字节（给反汇编窗口定上界）。不在任何条目里则 None。
    fn remaining(&self, addr: u64) -> Option<u64> {
        let i = self.eps.partition_point(|&e| e <= addr);
        if i == 0 {
            return None;
        }
        let end = self.ends[i - 1];
        (addr < end).then_some(end - addr)
    }
}

/// 枚举「一个指令表条目里的多个子 stub」，返回 **子 stub 地址 → 名字**。
///
/// 为什么需要单独一个入口：这些地址是条目的**内部**地址，既不是函数入口、也不是表项，
/// 所以任何「按表项遍历」的路径（`stub_rows`、`stub_eps`）都**结构上够不到它们**，
/// 而调用方是直接 `bl` 到它们的。material_3_demo 实测 **10 个这样的地址 / 4569 次调用**
/// （占全部直接调用 5.3%），全部落在 `0x3e0a84` 这一个 640 字节表项内、间隔恰好 0x20。
///
/// **判据比单块更严**：只有当表项长度是 32 的整数倍、且**每一个** 32 字节块都通过
/// `write_barrier_stub_name` 的形状校验时，才认为这个表项是「一族子 stub」并全部命名。
/// 部分匹配就一个都不命名——宁可少命名，也不要把「碰巧前 8 条像」的普通代码切开。
///
/// ⚠️ 先用**首块探针**再展开整条目：不这么做的话每个候选表项都要整段过一遍 capstone，
/// 是 24.8× 变慢的第二个来源（第一个是 `StubIdx` 那条 O(n²)）。
///
/// 只扫**没有被 Code 对象认领**的表项（与 stub 的定义一致）；有 Code 对象的是真函数，不切。
pub fn write_barrier_sub_stubs(analyzer: &Analyzer) -> BTreeMap<u64, String> {
    let mut out = BTreeMap::new();
    if analyzer.platform.arch != "arm64" {
        return out; // x64 形状未取证，不猜
    }
    let Ok(cs) = crate::disasm::build_cs(true) else {
        return out;
    };
    let rl = crate::export::asm::roles(analyzer);
    let fields = thread_field_names(
        &analyzer.profile.abi,
        &analyzer.platform.arch,
        analyzer.profile.compressed_pointers,
    );
    if fields.is_empty() {
        return out; // 没有该版本的 DartThread 布局 ⇒ 位移查不到名字 ⇒ 不命名
    }
    let claimed: BTreeSet<usize> = analyzer.func_eps.values().map(|(_, idx)| *idx).collect();
    let sidx = StubIdx::build(analyzer);
    for idx in 0..analyzer.pc_offsets.len() {
        if claimed.contains(&idx) {
            continue;
        }
        let Some((ep, size)) = analyzer.code_range(idx) else { continue };
        if size < 64 || size % 32 != 0 || size > 4096 {
            continue; // 少于 2 块、不是整齐块数组、或大得不像 stub 表
        }
        // 廉价探针：先看**首块**。绝大多数表项在这一步就被否掉，
        // 不必把整条目（可达数 KB）逐块交给 capstone——这是 24.8× slowdown 的第二个来源。
        let probe = disasm_stub(analyzer, &cs, ep, &sidx);
        let Some(probe) = probe.as_ref() else { continue };
        if write_barrier_stub_name(probe, true, &rl, &fields).is_none() {
            continue;
        }
        let nblk = (size / 32) as usize;
        let mut named: Vec<(u64, String)> = Vec::with_capacity(nblk);
        let mut all = true;
        for b in 0..nblk {
            let addr = ep + (b as u64) * 32;
            let got = disasm_stub(analyzer, &cs, addr, &sidx)
                .as_ref()
                .and_then(|i| write_barrier_stub_name(i, true, &rl, &fields));
            match got {
                Some(n) => named.push((addr, n)),
                None => {
                    all = false;
                    break;
                }
            }
        }
        if all && named.len() == nblk {
            out.extend(named);
        }
    }
    out
}


pub fn alloc_stubs_at(analyzer: &Analyzer, addrs: &[u64]) -> Vec<(u64, Option<String>)> {
    let is_arm64 = analyzer.platform.arch == "arm64";
    if !class_layer_usable(analyzer) {
        return addrs.iter().map(|a| (*a, None)).collect();
    }
    let Ok(cs) = crate::disasm::build_cs(is_arm64) else {
        return addrs.iter().map(|a| (*a, None)).collect();
    };
    // 角色寄存器与 DartThread 布局都是**每次调用只建一次**：write_barrier_stub_name 会被
    // 每个候选地址调一次，而这两样与地址无关（Roles 按值深拷贝曾造成过 33× 里的性能坑）。
    let rl = crate::export::asm::roles(analyzer);
    let fields = thread_field_names(
        &analyzer.profile.abi,
        &analyzer.platform.arch,
        analyzer.profile.compressed_pointers,
    );
    let stub_idx = StubIdx::build(analyzer);
    addrs
        .iter()
        .map(|a| {
            // ⚠️ **每地址只反汇编一次**，5 个命名器共用同一份指令列表。
            // 原先每个命名器各自反汇编自己的窗口，同一段字节最多被解码 5 次
            // （24 + 384 + 32 + ≤4096 + ≤4096 字节），`names+stubs` 因此占
            // 飞书全量导出的 45%。详见 `disasm_stub` 的文档。
            let ins = disasm_stub(analyzer, &cs, *a, &stub_idx);
            let Some(ins) = ins.as_ref() else { return (*a, None) };
            (
                *a,
                // 先试分配 stub（序言里的 class-id tag 字），认不出再试内联（胖）分配 stub，
                // 再试身份级命名（往 CODE_REG 里装的是哪个 *_stub 字段），
                // 然后是调用约定转换包装的形状，最后是「一个表项里的多个子 stub」（写屏障族）
                alloc_stub_name(ins, analyzer, is_arm64)
                    .or_else(|| inline_alloc_stub_name(ins, analyzer, is_arm64, &rl, &fields))
                    .or_else(|| code_reg_stub_name(ins, *a, is_arm64, &rl, &fields))
                    .or_else(|| runtime_stub_name(ins, *a, is_arm64))
                    .or_else(|| write_barrier_stub_name(ins, is_arm64, &rl, &fields)),
            )
        })
        .collect()
}
