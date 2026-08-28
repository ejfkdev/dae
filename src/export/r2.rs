//! DartDumper::Dump4Radare2 —— r2_script/addNames.r2（+ r2_dart_struct.h 模板拷贝）
//!
//! radare2 ≥ 6 兼容适配（6.2 实测）：
//! - flag 命名收紧：`$` 等字符被判非法 → 命名段清洗（注释文本保留原文）；
//! - `ic+` 无参形式（blutter 原版用法）在 r2 6 报 Usage 错误 → 改用 `CCu` 注释
//!   （旧版/新版通用，实测可写可读回）；
//! - 结构头导入命令是 `to r2_dart_struct.h`（r2 6 实测）。

use super::find_template;
use crate::analyzer::{Analyzer, LibGroups};
use crate::engine::restore::scrub_name;
use std::path::Path;

/// r2 6+ flag 命名清洗（仅用于 `f` 命令的命名段；实测 `$` 非法）
fn r2_seg(s: &str) -> String {
    s.replace('$', "_")
}

/// 非空段以 '.' 拼接并清洗（避免空类名产生 `..`/尾点这种非法 flag）
fn join_flag(parts: &[&str]) -> String {
    parts
        .iter()
        .filter(|p| !p.is_empty())
        .map(|p| r2_seg(p))
        .collect::<Vec<_>>()
        .join(".")
}

/// 双工具（r2 ≥6 / rizin）兼容的命令行：`s <addr>; <cmd>`。
/// rizin 的脚本解析器不接受 r2 的 `'@<addr>'` 临时寻址前缀（实测），
/// seek 对形式两工具均接受；本脚本一次性执行，seek 副作用无影响。
fn push_at(of: &mut String, ep: u64, cmd: &str) {
    of.push_str(&format!("s 0x{ep:x}; {cmd}\n"));
}

pub fn write(analyzer: &Analyzer, libs: &LibGroups, out_dir: &Path) -> Result<usize, String> {
    let dir = out_dir.join("r2_script");
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建 r2_script 目录失败: {e}"))?;
    let path = dir.join("addNames.r2");
    let mut of = String::new();
    // 首行 `#` 注释与 `e emu.str=true` 配置均不写：rizin 的脚本解析器不接受
    // 这两种行（r2 接受；经 r2 6.2 / rizin 0.9.1 实测后为双工具兼容而省略，
    // 两者对脚本本身并无影响）
    let app_base = analyzer.container.text_vmaddr.unwrap_or(0);
    // rizin 仅接受 `f name @ addr` 形式，且拒绝 addr=0x0 的 flag（r2 均接受），
    // 故占位 flag 只在非零时输出（heap_base 恒为 0x0 占位，直接省略）
    if app_base != 0 {
        of.push_str(&format!("f app.base @ 0x{app_base:x}\n"));
    }

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
                    // 注释原文不动（无校验），flag 段清洗
                    push_at(
                        &mut of,
                        f.ep,
                        &format!("CC Library(0x{:x}) = {lib_name}", lib_index + 1),
                    );
                    let lib_flag = r2_seg(lib_name);
                    if !lib_flag.is_empty() {
                        push_at(&mut of, f.ep, &format!("f lib.{lib_flag}"));
                    }
                    lib_printed = true;
                    lib_index += 1;
                }
                if !cls_printed {
                    push_at(
                        &mut of,
                        f.ep,
                        &format!("CC Class(0x{:x}) = {cls_name}", cls_index + 1),
                    );
                    let cls_flag = join_flag(&[lib_name, cls_name]);
                    if !cls_flag.is_empty() {
                        push_at(&mut of, f.ep, &format!("f class.{cls_flag}"));
                    }
                    cls_printed = true;
                    cls_index += 1;
                }
                let method_flag = join_flag(&[lib_name, cls_name, &f.mangled]);
                if !method_flag.is_empty() {
                    push_at(&mut of, f.ep, &format!("f method.{method_flag}"));
                }
                // 注释用 CCu（r2 6 的 ic+ 需额外 type 参数，CCu 新旧版通用）
                push_at(&mut of, f.ep, &format!("CCu {}.{}", cls_name, f.mangled));
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
                let clean_flag = r2_seg(&clean);
                push_at(&mut of, *ep, &format!("f method...{clean_flag}"));
                push_at(&mut of, *ep, &format!("CCu {clean}"));
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