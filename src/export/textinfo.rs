//! 纯文本信息产物（strings / libs / classes / functions / hierarchy / arrays / maps）。
//! 全部来自填解析阶段的既有数据，零额外解析：格式化写出、面向 grep / 无工具浏览。
//! 产物字节确定（HashMap 来源 entry 先按 ref 升序排序），不含中文。

use crate::analyzer::{Analyzer, LibGroups};
use crate::export::ppobjs::describe_into;
use std::fmt::Write as _;
use std::path::Path;

/// 六类文本产物的条数。
pub struct TextInfoCounts {
    pub strings: usize,
    pub libs: usize,
    pub classes: usize,
    pub functions: usize,
    pub arrays: usize,
    pub maps: usize,
}

/// Tab / 换行 / 反斜杠转义，保证一行一条、可安全粘贴/检索。
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

fn write_strings(analyzer: &Analyzer, out_dir: &Path) -> Result<usize, String> {
    let mut of = String::with_capacity(analyzer.iso.strings.len() * 48);
    for (r, v) in &analyzer.iso.strings {
        let text = v.as_deref().map(esc).unwrap_or_else(|| "<undecoded>".into());
        let _ = writeln!(of, "0x{r:x}\t{text}");
    }
    std::fs::write(out_dir.join("text").join("strings.txt"), of).map_err(|e| format!("写 strings.txt 失败: {e}"))?;
    Ok(analyzer.iso.strings.len())
}

fn write_libs(analyzer: &Analyzer, out_dir: &Path) -> Result<usize, String> {
    let mut of = String::with_capacity(analyzer.iso.libraries.len() * 64);
    for (r, rec) in &analyzer.iso.libraries {
        let url = analyzer.sref(rec.url_ref).unwrap_or_default();
        let name = analyzer.sref(rec.name_ref).unwrap_or_default();
        let _ = writeln!(of, "0x{r:x}\t{}\t{}", esc(url.as_str()), esc(name.as_str()));
    }
    std::fs::write(out_dir.join("text").join("libs.txt"), of).map_err(|e| format!("写 libs.txt 失败: {e}"))?;
    Ok(analyzer.iso.libraries.len())
}

fn write_classes(analyzer: &Analyzer, out_dir: &Path) -> Result<usize, String> {
    let mut of = String::with_capacity(analyzer.iso.classes.len() * 80);
    for (r, rec) in &analyzer.iso.classes {
        let name = analyzer
            .cname_by_cid
            .get(&rec.class_id)
            .cloned()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| analyzer.sref(rec.name_ref).unwrap_or_else(|| "?".to_string()));
        let lib = analyzer
            .lib_of(rec.library_ref)
            .and_then(|(_, u)| analyzer.sref(u))
            .unwrap_or_default();
        let _ = writeln!(
            of,
            "0x{r:x}\t{}\t{}\t{}",
            rec.class_id,
            esc(lib.as_str()),
            esc(name.as_str())
        );
    }
    std::fs::write(out_dir.join("text").join("classes.txt"), of).map_err(|e| format!("写 classes.txt 失败: {e}"))?;
    Ok(analyzer.iso.classes.len())
}

fn write_functions(libs: &LibGroups, out_dir: &Path) -> Result<usize, String> {
    let mut count = 0usize;
    let mut of = String::with_capacity(64 * 1024);
    for (lib_name, cls_map) in libs {
        for (cls_name, funcs) in cls_map {
            for f in funcs {
                if f.ep == 0 {
                    continue;
                }
                let _ = writeln!(
                    of,
                    "0x{ep:x}\t{}\t{}\t{}",
                    esc(lib_name),
                    esc(cls_name),
                    esc(&f.mangled),
                    ep = f.ep
                );
                count += 1;
            }
        }
    }
    std::fs::write(out_dir.join("text").join("functions.txt"), of).map_err(|e| format!("写 functions.txt 失败: {e}"))?;
    Ok(count)
}

fn write_arrays(analyzer: &Analyzer, out_dir: &Path) -> Result<usize, String> {
    let mut keys: Vec<u64> = analyzer.iso.array_elements.keys().copied().collect();
    keys.sort_unstable();
    let mut of = String::with_capacity(keys.len() * 48);
    for r in &keys {
        let mut d = String::new();
        describe_into(analyzer, &mut d, *r, 0);
        let _ = writeln!(of, "0x{r:x}\t{d}");
    }
    std::fs::write(out_dir.join("text").join("arrays.txt"), of).map_err(|e| format!("写 arrays.txt 失败: {e}"))?;
    Ok(keys.len())
}

fn write_maps(analyzer: &Analyzer, out_dir: &Path) -> Result<usize, String> {
    let mut keys: Vec<u64> = analyzer.iso.map_data.keys().copied().collect();
    keys.sort_unstable();
    let mut of = String::with_capacity(keys.len() * 48);
    for r in &keys {
        let mut d = String::new();
        describe_into(analyzer, &mut d, *r, 0);
        let _ = writeln!(of, "0x{r:x}\t{d}");
    }
    std::fs::write(out_dir.join("text").join("maps.txt"), of).map_err(|e| format!("写 maps.txt 失败: {e}"))?;
    Ok(keys.len())
}

/// 写全部六类文本产物，返回各条数。
pub fn write(analyzer: &Analyzer, libs: &LibGroups, out_dir: &Path) -> Result<TextInfoCounts, String> {
    let strings = write_strings(analyzer, out_dir)?;
    let libs_n = write_libs(analyzer, out_dir)?;
    let classes = write_classes(analyzer, out_dir)?;
    let functions = write_functions(libs, out_dir)?;
    let arrays = write_arrays(analyzer, out_dir)?;
    let maps = write_maps(analyzer, out_dir)?;
    Ok(TextInfoCounts {
        strings,
        libs: libs_n,
        classes,
        functions,
        arrays,
        maps,
    })
}