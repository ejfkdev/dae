//! `text/stubs.txt` —— **指令表里没有 Code 对象的条目索引**。
//!
//! AOT 的指令表是「stub 前缀 + 有 Code 对象的函数尾巴」两段（SDK
//! `Deserializer::GetCodeByIndex` 的注释：`code_index < first_entry_with_code`
//! 的条目只有入口点，Code 对象是共享的占位符）。dae 的 `functions.txt` 只列后者，
//! 于是「表里有、列表里没有」的条目在外面看不见——对拍同类工具时表现为「覆盖率少一截」
//! （实测 x64 语料 1608 条表项 vs 1258 个具名函数，缺的 176 条全是 stub）。
//!
//! 这个产物把它们如实列出来：入口、字节数、能否解出分配 stub 的类名（能解就写名字，
//! 解不出就留空——绝不为凑覆盖率编名字）。

use crate::analyzer::Analyzer;
use std::fmt::Write as _;
use std::path::Path;

pub struct StubCounts {
    pub total: usize,
    pub named: usize,
}

pub fn write(analyzer: &Analyzer, out_dir: &Path) -> Result<StubCounts, String> {
    // 「没有被任何 Code 对象认领」的表项：直接按 func_eps 的 idx 集合取补集，
    // 不依赖 first_entry / code_base_ref 的语义（实测那两个字段在本语料上都不指向 stub 段：
    // base_ref 之前的 167 个 Code 对象其实都是分配 stub，first_entry 却是 0）。
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

    let mut of = String::with_capacity(rows.len() * 48);
    let _ = writeln!(
        of,
        "// instruction-table entries without a Code object (stub prefix): {}",
        rows.len()
    );
    let mut named = 0usize;
    for (ep, size) in &rows {
        let name = names
            .iter()
            .find(|(a, _)| a == ep)
            .and_then(|(_, n)| n.clone())
            .unwrap_or_default();
        if !name.is_empty() {
            named += 1;
        }
        let _ = writeln!(of, "{ep:#x}\t{size}\tstub\t{name}");
    }
    std::fs::write(out_dir.join("text").join("stubs.txt"), of)
        .map_err(|e| format!("写 stubs.txt 失败: {e}"))?;
    Ok(StubCounts {
        total: rows.len(),
        named,
    })
}
