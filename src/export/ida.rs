//! IDA 导出：`ida_script/addNames.py`（IDAPython 命名脚本）+ `ida_dart_struct.h`（结构头）。
//!
//! API 选择对齐 IDA 9.x（9.3/9.4 真机实测）且兼容 8.x：
//! - 命名/边界：`ida_name.set_name` / `ida_funcs.add_func`（typed API，8.x+ 均存在）；
//! - 结构导入：`ida_typeinf.parse_decls` 传**文件内容字符串**（9.x 的「路径 + PT_FILE」
//!   形式已失效，实测 str 内容形式 0.43s 解析完 2.2MB 结构头）；8.x 用二参形式回退；
//! - `ida_struct` 模块 9.x 已删除，成员注释数据模板也不含 → 不做 per-member 注释。

use crate::analyzer::{Analyzer, LibGroups};
use crate::engine::restore::scrub_name;
use crate::export::R2_STRUCT_TEMPLATE;
use std::path::Path;

/// 写 ida_script/addNames.py + ida_dart_struct.h，返回命名函数条数。
pub fn write(analyzer: &Analyzer, _libs: &LibGroups, out_dir: &Path) -> Result<usize, String> {
    let dir = out_dir.join("ida_script");
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("创建 ida_script 目录失败: {e}"))?;

    // 结构头：与 r2 同源（blutter 派生的 Dart 结构，MIT 归因见文件头部）
    std::fs::write(dir.join("ida_dart_struct.h"), R2_STRUCT_TEMPLATE)
        .map_err(|e| format!("写 ida_dart_struct.h 失败: {e}"))?;

    let mut py = String::new();
    py.push_str("#!/usr/bin/env python3\n");
    py.push_str("# 由 dae 生成：Dart AOT 符号导入 IDA（IDAPython）。\n");
    py.push_str("# 用法：IDA 内 File → Script file... 选择本文件。\n");
    py.push_str("# API 对齐 IDA 9.x（typed API，9.3/9.4 实测）；8.x 预期兼容\n");
    py.push_str("# （同一批 API 自 7.x 存在，本机未装 8.x 实测）\n\n");
    py.push_str("import os\nimport idc\nimport ida_name\nimport ida_funcs\nimport ida_typeinf\nimport ida_nalt\n\n");
    py.push_str("print(\"[dae] importing Dart names into current IDB...\")\n\n");
    py.push_str("# 地址重定：MAC 可执行文件装载基址不为 0（如 0x100000000），ELF/Android 为 0\n");
    py.push_str("BN = ida_nalt.get_imagebase()\n");
    py.push_str("print(\"[dae] image base = {:#x}\".format(BN))\n\n");
    py.push_str("n_named = 0\nn_failed = 0\n\n");
    // set_name 带 SN_NOWARN(0x80)：目标为文件头 tail byte 等不可命名地址时静默计数，
    // 不再向 IDA 输出台刷 "can't rename byte..." 告警（去符号 exe 的快照回退场景必现）

    let mut count = 0usize;
    for (ep, name) in &analyzer.name_by_ep {
        if !analyzer.func_eps.values().any(|(e, _)| *e == *ep) {
            continue; // 与 addNames.r2 同口径：仅保留 code 表可达的函数
        }
        let clean = scrub_name(Some(name));
        if clean.is_empty() {
            continue;
        }
        let ida_name = format!("{clean}_{ep:x}");
        py.push_str(&format!(
            "if ida_name.set_name({ep:#x} + BN, \"{ida_name}\", 0x80):\n"
        ));
        py.push_str("    n_named += 1\nelse:\n    n_failed += 1\n");
        if let Some(&(_, idx)) = analyzer
            .func_eps
            .iter()
            .find(|(_, (e, _))| *e == *ep)
            .map(|(_, v)| v)
        {
            let size = analyzer.code_size(idx);
            if size > 0 {
                py.push_str(&format!(
                    "ida_funcs.add_func({ep:#x} + BN, {:#x} + BN)\n",
                    *ep + size
                ));
            }
        }
        count += 1;
    }
    py.push_str(&format!(
        "print(\"[dae] names: {{}} named, {{}} failed\".format(n_named, n_failed))\n\n",
    ));

    py.push_str("\n");
    py.push_str("def _create_dart_structs():\n");
    py.push_str("    \"\"\"导入 DartThread/DartObjectPool 结构（9.x 用 str 内容形式，8.x 回退二参形式）\"\"\"\n");
    py.push_str("    hdr = os.path.join(os.path.dirname(os.path.abspath(__file__)), \"ida_dart_struct.h\")\n");
    py.push_str("    with open(hdr, \"r\", encoding=\"utf-8\", errors=\"replace\") as f:\n");
    py.push_str("        content = f.read()\n");
    py.push_str("    til = ida_typeinf.get_idati()\n");
    py.push_str("    rc = None\n");
    py.push_str("    for args in ((til, content, None, 0), (til, content)):\n");
    py.push_str("        try:\n");
    py.push_str("            rc = ida_typeinf.parse_decls(*args)\n");
    py.push_str("            break\n");
    py.push_str("        except TypeError:\n");
    py.push_str("            continue\n");
    py.push_str("    s_thread = idc.get_struc_id(\"DartThread\")\n");
    py.push_str("    s_pool = idc.get_struc_id(\"DartObjectPool\")\n");
    py.push_str("    print(\"[dae] structs: DartThread={}, DartObjectPool={} (parse_rc={})\".format(\n");
    py.push_str("        s_thread, s_pool, rc))\n");
    py.push_str("    if s_thread == idc.BADADDR or s_pool == idc.BADADDR:\n");
    py.push_str("        print(\"[dae] struct import failed — 可手动 File → Load file → Parse C header file 导入 ida_dart_struct.h\")\n\n");
    py.push_str("_create_dart_structs()\n");
    py.push_str("print(\"[dae] done.\")\n");

    std::fs::write(dir.join("addNames.py"), py)
        .map_err(|e| format!("写 addNames.py 失败: {e}"))?;
    Ok(count)
}