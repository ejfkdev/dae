//! `text/stubs.txt` —— **指令表里没有被任何 Function 对象引用的条目索引**。
//!
//! `functions.txt` 只列「有 Function 对象引用」的表项，于是剩下的在外面看不见——
//! 对拍同类工具时表现为「覆盖率少一截」（实测 x64 语料 1608 条表项 vs 1258 个具名函数）。
//! 这个产物把它们如实列出来：入口、字节数、能否解出名字（能解就写，解不出就留空——
//! **绝不为凑覆盖率编名字**）。
//!
//! ⚠️ **判据是「没被 Function 引用」，不是「没有 Code 对象」**——后者 dae 并不检查。
//! 早先的表头与文档都写成「without a Code object (stub prefix)」，两处都不成立，已实测更正：
//! * **不是前缀**：Reqable（`first_entry_with_code` = 48 455）的 46 723 条里有 **7 798 条
//!   的下标 ≥ first_entry**，同时有 **9 530 个已命名函数**的下标 < first_entry ⇒ 两类是交错的。
//! * **不全是 stub**：Reqable 有 **24 932 条（53.4%、合计 8.09 MB）**、飞书有
//!   **43 195 条（72.3%、14.67 MB）** 以教科书式的 Dart `EnterFrame` 序言开头
//!   （`stp x29,x30,[x15,#-0x10]!` + `mov x29,x15`），条目长度中位数 180 字节、最长 27 708 字节
//!   ——**它们是函数体，不是 stub**。而 `first_entry_with_code == 0` 的语料（material_3_demo /
//!   微博 / ChatGLM）里这一比例只有 **0.4–1.2%**。所以这个现象**只与 `first_entry_with_code > 0`
//!   相关**，与压缩指针无关（微博/ChatGLM 都是压缩指针、比例却极低）。
//!   aotopsy 把这一段描述为「discarded Code objects」（`--split-debug-info`/`--obfuscate` 构建），
//!   并对全部 57 960 条都出反汇编；dae 目前只反编译被 Function 引用的那 11 237 条。
//!   **这是 dae 在移动端最大的未覆盖代码块，尚未定性、也没有照印成名字**，见 docs/DECOMPILER.md。

use std::io::Write as _;
use crate::analyzer::Analyzer;
use std::path::Path;

pub struct StubCounts {
    pub total: usize,
    pub named: usize,
}

/// 一行 = `(入口, 字节数, 解出的名字)`；名字解不出就是空串（**绝不为凑覆盖率编名字**）。
///
/// `write`（产物 `text/stubs.txt`）与 `dae stubs`（查询命令）共用这一处，所以两边看到的
/// 一定是同一批条目、同一套名字。
pub fn stub_rows(analyzer: &Analyzer) -> Vec<(u64, u64, String)> {
    // 「没有被任何 Function 对象引用」的表项：直接按 func_eps 的 idx 集合取补集。
    // ⚠️ 刻意**不**用 first_entry / code_base_ref 的语义去分段——实测那两个字段都不指向
    // 「stub 段」：base_ref 之前的 167 个 Code 对象其实都是分配 stub；而 Reqable 的
    // first_entry=48 455 两侧**都**同时含有已命名函数与未被引用的表项（9 530 / 7 798）。
    let claimed: std::collections::BTreeSet<usize> =
        analyzer.func_eps.values().map(|(_, idx)| *idx).collect();
    let mut rows: Vec<(u64, u64)> = Vec::new();
    for idx in 0..analyzer.pc_offsets.len() {
        if claimed.contains(&idx) {
            continue;
        }
        if let Some((ep, size)) = analyzer.code_range(idx) {
            rows.push((ep, size));
        }
    }
    // 分配 stub 的类名：与调用图共用同一套解码（序言里的 class-id tag 字），
    // 门禁 `alloc_stub_naming` 盯着「零编造」。
    #[cfg(feature = "asm")]
    let names = {
        let addrs: Vec<u64> = rows.iter().map(|(ep, _)| *ep).collect();
        crate::export::callgraph::alloc_stubs_at(analyzer, &addrs)
    };
    #[cfg(not(feature = "asm"))]
    let names: Vec<(u64, Option<String>)> = rows.iter().map(|(ep, _)| (*ep, None)).collect();

    // 原来是每行都 `names.iter().find(...)` 线性找一遍（O(n²)：2757 条 stub 就是 760 万次
    // 比较）。换成查表；**首个命中优先**（`or_insert`）以保持与 `find` 完全相同的语义——
    // 同一地址若出现两次，取的是先出现的那个。
    let mut by_ep: std::collections::BTreeMap<u64, String> = std::collections::BTreeMap::new();
    for (a, n) in names {
        if let Some(n) = n {
            by_ep.entry(a).or_insert(n);
        }
    }
    rows.into_iter()
        .map(|(ep, size)| (ep, size, by_ep.get(&ep).cloned().unwrap_or_default()))
        .collect()
}

pub fn write(analyzer: &Analyzer, out_dir: &Path) -> Result<StubCounts, String> {
    let rows = stub_rows(analyzer);
    let mut of = crate::export::stream_writer(&out_dir.join("text"), "stubs.txt")?;
    let _ = writeln!(
        of,
        "// instruction-table entries not referenced by any Function (stubs and, on some builds, unnamed function bodies): {}",
        rows.len()
    );
    let mut named = 0usize;
    for (ep, size, name) in &rows {
        if !name.is_empty() {
            named += 1;
        }
        let _ = writeln!(of, "{ep:#x}\t{size}\tstub\t{name}");
    }
    crate::export::finish_writer(of, "stubs.txt")?;
    Ok(StubCounts {
        total: rows.len(),
        named,
    })
}
