//! FridaWriter::Create —— frida.js：模板 + 常量 + Classes 数组。
//! 与参考实现一致（对拍验证过 100% 逐条一致），外加按 Profile 重写模板顶部
//! 三个运行时常量（参考实现漏写，见 export/mod.rs 头注）。

use crate::analyzer::Analyzer;
use std::path::Path;

const TEMPLATE: &str = include_str!("../../templates/frida.template.js");

pub fn write(analyzer: &Analyzer, out_dir: &Path) -> Result<usize, String> {
    let mut out = String::new();
    // 模板：PointerCompressedEnabled / CompressedWordSize / HeapAddressReg 按 Profile 重写
    let compressed = if analyzer.profile.compressed_pointers { "true" } else { "false" };
    let replaced = TEMPLATE
        .replace(
            "const PointerCompressedEnabled = true;",
            &format!("const PointerCompressedEnabled = {compressed};"),
        )
        .replace(
            "const CompressedWordSize = 4;",
            &format!("const CompressedWordSize = {};", analyzer.profile.word_size),
        )
        .replace(
            "const HeapAddressReg = 'x28';",
            &format!(
                "const HeapAddressReg = '{}';",
                analyzer.platform.frida_heap_address_reg
            ),
        );
    out.push_str(&replaced);

    for (name, val) in &analyzer.profile.frida_cid_constants {
        out.push_str(&format!("const {name} = {val};\n"));
    }
    out.push_str("const Classes = [\n");

    // by_id：iso 覆盖（后见生效），vm setdefault（先见生效）——与参考实现一致
    let mut by_id: std::collections::BTreeMap<i64, (u64, crate::engine::snapshot::ClassRec)> =
        std::collections::BTreeMap::new();
    for (&ref_, c) in analyzer.iso.classes.iter() {
        if (c.class_id as u64) < (1 << 20) {
            by_id.insert(c.class_id, (ref_, *c));
        }
    }
    for (&ref_, c) in analyzer.vm.classes.iter() {
        if (c.class_id as u64) < (1 << 20) {
            by_id.entry(c.class_id).or_insert((ref_, *c));
        }
    }
    let max_id = by_id.keys().copied().max().unwrap_or(-1);
    for cid in 0..=max_id {
        let item = by_id.get(&cid).map(|(ref_, c)| (*ref_, *c));
        match analyzer.class_entry_string(cid, item) {
            Some(s) => out.push_str(&format!("{s},\n")),
            None => out.push_str("null,\n"),
        }
    }
    out.push_str("];\n");

    let path = out_dir.join("frida.js");
    std::fs::write(&path, out).map_err(|e| format!("写 frida.js 失败: {e}"))?;
    Ok((max_id.max(-1) + 1) as usize)
}