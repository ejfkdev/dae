//! DartDumper::Dump4Radare2 —— r2_script/addNames.r2（+ r2_dart_struct.h 模板拷贝）

use super::find_template;
use crate::analyzer::{Analyzer, LibGroups};
use crate::engine::restore::scrub_name;
use crate::export::hex_noprefix_py;
use std::path::Path;

pub fn write(analyzer: &Analyzer, libs: &LibGroups, out_dir: &Path) -> Result<usize, String> {
    let dir = out_dir.join("r2_script");
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建 r2_script 目录失败: {e}"))?;
    let path = dir.join("addNames.r2");
    let mut of = String::new();
    of.push_str("# create flags for libraries, classes and methods\n");
    of.push_str("e emu.str=true\n");
    let app_base = analyzer.container.text_vmaddr.unwrap_or(0);
    of.push_str(&format!("f app.base = 0x{:x}\n", app_base));
    of.push_str("f app.heap_base = 0x0\n");

    let mut count = 0usize;
    let mut lib_index: u64 = 0;
    for (lib_name, cls_map) in libs {
        let mut lib_printed = false;
        let mut cls_index: u64 = 0;
        for (cls_name, funcs) in cls_map {
            let mut cls_printed = false;
            for f in funcs {
                if f.ep == 0 {
                    continue;
                }
                if !lib_printed {
                    of.push_str(&format!(
                        "'@0x{}'CC Library(0x{:x}) = {lib_name}\n",
                        hex_noprefix_py(f.ep as i64),
                        lib_index + 1
                    ));
                    of.push_str(&format!("'@0x{}'f lib.{lib_name}\n", hex_noprefix_py(f.ep as i64)));
                    lib_printed = true;
                    lib_index += 1;
                }
                if !cls_printed {
                    of.push_str(&format!(
                        "'@0x{}'CC Class(0x{:x}) = {cls_name}\n",
                        hex_noprefix_py(f.ep as i64),
                        cls_index + 1
                    ));
                    of.push_str(&format!(
                        "'@0x{}'f class.{lib_name}.{cls_name}\n",
                        hex_noprefix_py(f.ep as i64)
                    ));
                    cls_printed = true;
                    cls_index += 1;
                }
                of.push_str(&format!(
                    "'@0x{}'f method.{lib_name}.{cls_name}.{}\n",
                    hex_noprefix_py(f.ep as i64),
                    f.mangled
                ));
                of.push_str(&format!(
                    "'@0x{}'ic+.{cls_name}.{}\n",
                    hex_noprefix_py(f.ep as i64),
                    f.mangled
                ));
                count += 1;
            }
        }
    }
    // ELF 强制回填补充：name_by_ep 中存在但不在 build_functions 输出中的条目（2.19.6 等
    // 函数簇漂移导致 code_index 错误 → 无 func_eps 记录的入口）
    for (ep, name) in &analyzer.name_by_ep {
        if !analyzer.func_eps.values().any(|(e, _)| *e == *ep) {
            let clean = scrub_name(Some(name));
            if !clean.is_empty() {
                of.push_str(&format!("'@0x{}'f method...{clean}\n", hex_noprefix_py(*ep as i64)));
                of.push_str(&format!("'@0x{}'ic+..{clean}\n", hex_noprefix_py(*ep as i64)));
                count += 1;
            }
        }
    }
    // 复用 blutter 的静态 struct 头（Dart SDK 固定布局，非快照衍生）。
    // 磁盘模板优先（开发时临时改版）；找不到时用内嵌副本兜底，
    // 保证单文件发布二进制（Releases/brew）也能产出 r2_dart_struct.h。
    match find_template("r2_dart_struct.h") {
        Some(src) => {
            let _ = std::fs::copy(src, dir.join("r2_dart_struct.h"));
        }
        None => {
            let _ = std::fs::write(dir.join("r2_dart_struct.h"), crate::export::R2_STRUCT_TEMPLATE);
        }
    }
    std::fs::write(&path, of).map_err(|e| format!("写 addNames.r2 失败: {e}"))?;
    Ok(count)
}