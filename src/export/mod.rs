//! 七类导出（与 blutter / 参考实现格式对齐）：
//! r2_script/addNames.r2、ida_script/addNames.py、frida.js、asm/、pp.txt、objs.txt
//! （另附 r2/ida 共用的 Dart 结构头 r2_dart_struct.h / ida_dart_struct.h）。
//!
//! 与 Python 参考实现的三处有意修正（README 有说明）：
//! 1. addNames.r2 的 Library()/Class() 编号正确自增（参考实现漏了自增）；
//! 2. addNames.r2 的 app.base 取容器 __TEXT 段 VM 地址（参考实现硬编码 0x106484000）；
//! 3. frida 模板的 PointerCompressedEnabled/CompressedWordSize/HeapAddressReg 按 Profile 重写。

pub mod frida;
pub mod ida;
pub mod ppobjs;
pub mod r2;
pub mod struct_hdr;
pub mod textinfo;
#[cfg(feature = "asm")]
pub mod asm;

use crate::analyzer::Analyzer;
use std::path::Path;

/// 与 r2 同源的 Dart 结构头模板（r2_dart_struct.h 与 ida_dart_struct.h 共用；
/// blutter 派生，MIT 归因见文件头部）
pub(crate) const R2_STRUCT_TEMPLATE: &str = include_str!("../../templates/r2_dart_struct.h");

pub struct ExportSummary {
    pub r2_functions: usize,
    pub ida_functions: usize,
    pub frida_classes: usize,
    pub pp_entries: usize,
    pub objs_instances: usize,
    pub asm_functions: usize,
    pub asm_enabled: bool,
    pub textinfo: textinfo::TextInfoCounts,
}

/// DART_AOT_TIMINGS=1 时打印导出阶段耗时
#[inline]
fn t(name: &str, since: &mut std::time::Instant) {
    if std::env::var("DART_AOT_TIMINGS").is_ok() {
        let now = std::time::Instant::now();
        eprintln!("[timing] {name}: {:?}", now.duration_since(*since));
        *since = now;
    }
}

pub fn run(analyzer: &Analyzer, out_dir: &Path) -> Result<ExportSummary, String> {
    std::fs::create_dir_all(out_dir)
        .map_err(|e| format!("无法创建输出目录 {}: {e}", out_dir.display()))?;
    std::fs::create_dir_all(out_dir.join("text"))
        .map_err(|e| format!("无法创建输出子目录 text: {e}"))?;

    let mut since = std::time::Instant::now();
    // r2 全量（含 dart: 内部库，保证反编译工具里 SDK 函数也有还原名）；
    // asm 聚焦应用代码（跳过 dart: 内部库，控制产物规模）。
    let libs_r2 = analyzer.build_functions(true);
    let libs_asm = analyzer.build_functions(false);
    let libs_ref = &libs_r2;
    let libs_asm_ref = &libs_asm;
    t("build_functions", &mut since);

    // 四个导出任务相互独立（写不同文件），铺平并行：
    // asm/ppobjs 内部各自分块并行，r2/frida 轻量
    let asm_enabled = cfg!(feature = "asm");
    let do_asm = asm_enabled && analyzer.platform.arch == "arm64";
    enum TaskDone {
        R2(Result<usize, String>),
        Ida(Result<usize, String>),
        Frida(Result<usize, String>),
        Asm(Result<usize, String>),
        PpObjs(Result<(usize, usize), String>),
        TextInfo(Result<textinfo::TextInfoCounts, String>),
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        {
            let tx = tx.clone();
            scope.spawn(move || {
                let _ = tx.send(TaskDone::R2(r2::write(analyzer, libs_ref, out_dir)));
            });
        }
        {
            let tx = tx.clone();
            scope.spawn(move || {
                let _ = tx.send(TaskDone::Ida(ida::write(analyzer, libs_ref, out_dir)));
            });
        }
        {
            let tx = tx.clone();
            scope.spawn(move || {
                let _ = tx.send(TaskDone::Frida(frida::write(analyzer, out_dir)));
            });
        }
        #[cfg(feature = "asm")]
        {
            let tx = tx.clone();
            scope.spawn(move || {
                let r = if do_asm {
                    asm::write(analyzer, libs_asm_ref, out_dir)
                } else {
                    Ok(0)
                };
                let _ = tx.send(TaskDone::Asm(r));
            });
        }
        {
            let tx = tx.clone();
            scope.spawn(move || {
                let _ = tx.send(TaskDone::PpObjs(ppobjs::write(analyzer, out_dir)));
            });
        }
        {
            let tx = tx.clone();
            scope.spawn(move || {
                let _ = tx.send(TaskDone::TextInfo(textinfo::write(analyzer, libs_ref, out_dir)));
            });
        }
        drop(tx);
    });

    let mut n_r2 = 0usize;
    let mut n_ida = 0usize;
    let mut n_frida = 0usize;
    let mut n_pp = 0usize;
    let mut n_objs = 0usize;
    let mut asm_functions = 0usize;
    let mut textinfo: Option<textinfo::TextInfoCounts> = None;
    for done in rx {
        match done {
            TaskDone::R2(Ok(n)) => n_r2 = n,
            TaskDone::Ida(Ok(n)) => n_ida = n,
            TaskDone::Frida(Ok(n)) => n_frida = n,
            TaskDone::Asm(Ok(n)) => asm_functions = n,
            TaskDone::PpObjs(Ok((p, o))) => {
                n_pp = p;
                n_objs = o;
            }
            TaskDone::TextInfo(Ok(t)) => textinfo = Some(t),
            TaskDone::R2(Err(e))
            | TaskDone::Ida(Err(e))
            | TaskDone::Frida(Err(e))
            | TaskDone::Asm(Err(e))
            | TaskDone::PpObjs(Err(e))
            | TaskDone::TextInfo(Err(e)) => return Err(e),
        }
    }
    if asm_enabled && !do_asm {
        eprintln!(
            "note: IL disassembly is currently arm64-only (platform profile arch={}); skipping asm/",
            analyzer.platform.arch
        );
    }
    t("exports(并行管线)", &mut since);

    Ok(ExportSummary {
        r2_functions: n_r2,
        ida_functions: n_ida,
        frida_classes: n_frida,
        pp_entries: n_pp,
        objs_instances: n_objs,
        asm_functions,
        asm_enabled,
        textinfo: textinfo.unwrap_or(textinfo::TextInfoCounts {
            strings: 0,
            libs: 0,
            classes: 0,
            functions: 0,
            arrays: 0,
            maps: 0,
        }),
    })
}

/// Python `%#x` 风格的十六进制（负数输出 -0x..，与 Rust 原生 {:#x} 不同）；用 i128 防溢出
pub fn hex_py(v: i64) -> String {
    if v < 0 {
        format!("-{:#x}", (v as i128).unsigned_abs())
    } else {
        format!("{:#x}", v)
    }
}

/// Python `%x` 风格（负数输出 -...，与上述同理）
pub fn hex_noprefix_py(v: i64) -> String {
    if v < 0 {
        format!("-{:x}", (v as i128).unsigned_abs())
    } else {
        format!("{:x}", v)
    }
}