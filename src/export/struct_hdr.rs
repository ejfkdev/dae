//! 组装 r2_dart_struct.h / ida_dart_struct.h（per-target 生成的自身产物）。
//!
//! 由两段拼成：
//! 1. `DartThread`：按 (SDK abi, 平台架构) 取 profiles/struct 里编译 Dart VM 得到的精确布局，
//!    未覆盖的版本/架构回退到内嵌静态模板里的旧 DartThread 段（仅防御性，正常到不了）；
//! 2. `DartObjectPool`：按目标快照的实际对象池条目动态生成（条目地址 = 0x10 + 8*i，
//!    与 pp.txt 的 `[pp+0x..]` 偏移一致），字段名按条目类型区分（Obj/IMM/NativeFn/Stub）。
//!
//! 旧实现整份拷贝 blutter 的 98k 行静态模板——其中的 DartObjectPool 是单个二进制烘焙值，
//! 对任何其它目标（不同 SDK / 不同对象池长度）都是错位或错误的；DartThread 也只对应某
//! 一个 SDK。现改为 per-target 生成，结构体尺寸与偏移才与被分析二进制真实对齐。

use crate::analyzer::Analyzer;
use crate::engine::snapshot::PoolKind;
use crate::export::R2_STRUCT_TEMPLATE;
use std::fmt::Write as _;

/// 内嵌静态模板里的 DartThread 段（回退用）：`typedef struct DartThread {` 至 `} DartThread;`。
fn fallback_dart_thread() -> &'static str {
    let s: &str = R2_STRUCT_TEMPLATE;
    let start = s.find("typedef struct DartThread {");
    let end = s.find("} DartThread;");
    match (start, end) {
        (Some(a), Some(b)) => &s[a..b + "} DartThread;".len()],
        _ => s,
    }
}

/// 按对象池条目动态生成 DartObjectPool。
fn build_object_pool(analyzer: &Analyzer) -> String {
    let n = analyzer
        .iso
        .objectpool_entries
        .as_ref()
        .map(|v| v.len())
        .unwrap_or(0);
    let mut s = String::with_capacity(64 + n * 40);
    s.push_str("typedef struct DartObjectPool {\n\t__int64 pad0;\n\t__int64 pad1;\n");
    if let Some(entries) = analyzer.iso.objectpool_entries.as_ref() {
        for (i, ent) in entries.iter().enumerate() {
            let off = 0x10 + i * 8;
            let name = match ent.typ {
                PoolKind::Obj => format!("Obj_0x{off:x}"),
                PoolKind::Imm => format!("IMM_0x{off:x}"),
                PoolKind::Native => format!("NativeFn_0x{off:x}"),
                PoolKind::Stub => format!("Stub_0x{off:x}"),
            };
            let _ = writeln!(s, "\t__int64 {name};");
        }
    }
    s.push_str("} DartObjectPool;\n");
    s
}

/// 压缩指针构建要在 `write_barrier_mask` 之后补一个 `heap_base`。
///
/// SDK `runtime/vm/thread.h` 里 `heap_base_` 是 `#if defined(DART_COMPRESSED_POINTERS)`
/// 包着的**条件字段**，而且是 `Thread` 里唯一一个（3.3.4 与 3.13.0 各只有 3 处该宏，
/// 另两处是访问器方法）。所以压缩构建里它之后的每个字段都比非压缩布局晚 8 字节。
/// 仓库里 48 份头文件对此**不一致**：2.13.4–2.19.6 已含 `heap_base`，其余不含。
/// 规则因此是「目标压缩 **且** 头里没有」才插——已经有就不动
/// （weibo 是 dart 2.19.6 压缩构建、头里已有 `heap_base`@0x48，其屏障表装载
/// `[x26,#0x248]` 在头里正是 `write_barrier_entry_point`，两端对得上）。
///
/// ⚠️ 不插的后果不只是命名：`DartThread` 是**发给 IDA/r2 的结构体**，
/// 压缩指针（＝每一个移动端 Flutter 产物）会从 `write_barrier_mask` 之后整体错位 8 字节，
/// 用户在 IDA 里按结构体读线程字段会全错。这一条比 stub 命名严重得多。
pub fn with_heap_base(hdr: &str, compressed: bool) -> String {
    if !compressed || hdr.contains("heap_base") {
        return hdr.to_string();
    }
    let mut out = String::with_capacity(hdr.len() + 32);
    let mut done = false;
    for ln in hdr.lines() {
        out.push_str(ln);
        out.push('\n');
        if !done && ln.trim_end().trim_end_matches(';').ends_with("write_barrier_mask") {
            out.push_str("\t__int64 heap_base;\n");
            done = true;
        }
    }
    out
}

/// 组装完整结构头（r2 与 ida 共用）。
pub(crate) fn build(analyzer: &Analyzer) -> String {
    let mut out = String::with_capacity(16 * 1024);
    match crate::struct_tables::dart_thread(&analyzer.profile.abi, &analyzer.platform.arch) {
        Some(t) => out.push_str(&with_heap_base(t, analyzer.profile.compressed_pointers)),
        None => out.push_str(fallback_dart_thread()),
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    out.push_str(&build_object_pool(analyzer));
    out
}