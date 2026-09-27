//! 纯文本信息产物（strings / libs / classes / functions / hierarchy / arrays / maps）。
//! 全部来自填解析阶段的既有数据，零额外解析：格式化写出、面向 grep / 无工具浏览。
//! 产物字节确定（HashMap 来源 entry 先按 ref 升序排序），不含中文。

use std::io::Write;
use crate::analyzer::{Analyzer, LibGroups};
use crate::export::ppobjs::describe_into;
use std::path::Path;

/// 六类文本产物的条数。
pub struct TextInfoCounts {
    pub strings: usize,
    pub libs: usize,
    pub classes: usize,
    pub functions: usize,
    pub arrays: usize,
    pub maps: usize,
    /// 具名字段条数（Field 簇 + 访问器名推断；见 src/decompiler.rs）
    pub fields: usize,
}

/// Tab / 换行 / 反斜杠转义，保证一行一条、可安全粘贴/检索。
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

fn write_strings(analyzer: &Analyzer, out_dir: &Path) -> Result<usize, String> {
    let mut of = crate::export::stream_writer(&out_dir.join("text"), "strings.txt")?;
    for (r, v) in &analyzer.iso.strings {
        let text = v.as_deref().map(esc).unwrap_or_else(|| "<undecoded>".into());
        let _ = writeln!(of, "0x{r:x}\t{text}");
    }
    crate::export::finish_writer(of, "strings.txt")?;
    Ok(analyzer.iso.strings.len())
}

fn write_libs(analyzer: &Analyzer, out_dir: &Path) -> Result<usize, String> {
    let mut of = crate::export::stream_writer(&out_dir.join("text"), "libs.txt")?;
    for (r, rec) in &analyzer.iso.libraries {
        let url = analyzer.sref(rec.url_ref).unwrap_or_default();
        let name = analyzer.sref(rec.name_ref).unwrap_or_default();
        let _ = writeln!(of, "0x{r:x}\t{}\t{}", esc(url.as_str()), esc(name.as_str()));
    }
    crate::export::finish_writer(of, "libs.txt")?;
    Ok(analyzer.iso.libraries.len())
}

fn write_classes(analyzer: &Analyzer, out_dir: &Path) -> Result<usize, String> {
    let mut of = crate::export::stream_writer(&out_dir.join("text"), "classes.txt")?;
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
    crate::export::finish_writer(of, "classes.txt")?;
    Ok(analyzer.iso.classes.len())
}

fn write_functions(libs: &LibGroups, out_dir: &Path) -> Result<usize, String> {
    let mut count = 0usize;
    let mut of = crate::export::stream_writer(&out_dir.join("text"), "functions.txt")?;
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
    crate::export::finish_writer(of, "functions.txt")?;
    Ok(count)
}

fn write_arrays(analyzer: &Analyzer, out_dir: &Path) -> Result<usize, String> {
    let mut keys: Vec<u64> = analyzer.iso.array_elements.keys().copied().collect();
    keys.sort_unstable();
    let mut of = crate::export::stream_writer(&out_dir.join("text"), "arrays.txt")?;
    for r in &keys {
        let mut d = String::new();
        describe_into(analyzer, &mut d, *r, 0);
        let _ = writeln!(of, "0x{r:x}\t{d}");
    }
    crate::export::finish_writer(of, "arrays.txt")?;
    Ok(keys.len())
}

fn write_maps(analyzer: &Analyzer, out_dir: &Path) -> Result<usize, String> {
    let mut keys: Vec<u64> = analyzer.iso.map_data.keys().copied().collect();
    keys.sort_unstable();
    let mut of = crate::export::stream_writer(&out_dir.join("text"), "maps.txt")?;
    for r in &keys {
        let mut d = String::new();
        describe_into(analyzer, &mut d, *r, 0);
        let _ = writeln!(of, "0x{r:x}\t{d}");
    }
    crate::export::finish_writer(of, "maps.txt")?;
    Ok(keys.len())
}

/// 写全部六类文本产物，返回各条数。
/// 具名字段：类 \t 字段 \t 来源 \t 字节偏移。
/// 来源两列：`rec` = 快照 Field 簇直接写着（偏移来自 Mint 值）；
/// `accessor` = 隐式 getter/setter 名推断（偏移来自机器码位移）。都是可证的，
/// 没解出来的字段不写占位行——AOT 丢掉了 97% 以上的字段名，凭空补名是编造。
fn write_fields(analyzer: &Analyzer, out_dir: &Path) -> Result<usize, String> {
    let rows = analyzer.field_rows();
    let mut of = crate::export::stream_writer(&out_dir.join("text"), "fields.txt")?;
    for r in &rows {
        let _ = writeln!(of, "{}\t{}\t{}\t{:#x}", r.class, r.name, r.source, r.off);
    }
    crate::export::finish_writer(of, "fields.txt")?;
    Ok(rows.len())
}

pub fn write(analyzer: &Analyzer, libs: &LibGroups, out_dir: &Path) -> Result<TextInfoCounts, String> {
    let strings = write_strings(analyzer, out_dir)?;
    let libs_n = write_libs(analyzer, out_dir)?;
    let classes = write_classes(analyzer, out_dir)?;
    let functions = write_functions(libs, out_dir)?;
    let arrays = write_arrays(analyzer, out_dir)?;
    let maps = write_maps(analyzer, out_dir)?;
    let fields = write_fields(analyzer, out_dir)?;
    Ok(TextInfoCounts {
        strings,
        libs: libs_n,
        classes,
        functions,
        arrays,
        maps,
        fields,
    })
}