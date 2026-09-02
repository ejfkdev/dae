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
            let name = match ent.typ.as_str() {
                "obj" => format!("Obj_0x{off:x}"),
                "imm" => format!("IMM_0x{off:x}"),
                "native" => format!("NativeFn_0x{off:x}"),
                _ => format!("Stub_0x{off:x}"),
            };
            let _ = writeln!(s, "\t__int64 {name};");
        }
    }
    s.push_str("} DartObjectPool;\n");
    s
}

/// 组装完整结构头（r2 与 ida 共用）。
pub(crate) fn build(analyzer: &Analyzer) -> String {
    let mut out = String::with_capacity(16 * 1024);
    match crate::struct_tables::dart_thread(&analyzer.profile.abi, &analyzer.platform.arch) {
        Some(t) => out.push_str(t),
        None => out.push_str(fallback_dart_thread()),
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    out.push_str(&build_object_pool(analyzer));
    out
}