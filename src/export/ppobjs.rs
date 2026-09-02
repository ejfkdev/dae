//! pp.txt（对象池条目 dump）+ objs.txt（用户类实例递归 dump）。
//! 描述逻辑对齐参考实现 describe_obj / _field_val / _instance_block；
//! 输出全部直接写入预分配缓冲（sink 式），field 递归不克隆字符串、不建临时 Vec。

use crate::analyzer::Analyzer;
use crate::engine::snapshot::FieldVal;
use crate::export::hex_py;
use std::fmt::Write as _;
use std::path::Path;

#[inline]
fn t(name: &str, since: &mut std::time::Instant) {
    if std::env::var("DART_AOT_TIMINGS").is_ok() {
        let now = std::time::Instant::now();
        eprintln!("[timing] {name}: {:?}", now.duration_since(*since));
        *since = now;
    }
}

/// 返回 (pp 条目数, objs 实例数)
pub fn write(analyzer: &Analyzer, out_dir: &Path) -> Result<(usize, usize), String> {
    let mut since = std::time::Instant::now();
    let n_pp = write_pp(analyzer, out_dir)?;
    t("pp", &mut since);
    let n_objs = write_objs(analyzer, out_dir)?;
    t("objs", &mut since);
    Ok((n_pp, n_objs))
}

fn write_pp(analyzer: &Analyzer, out_dir: &Path) -> Result<usize, String> {
    let Some(entries) = analyzer.iso.objectpool_entries.as_ref() else {
        return Ok(0); // 无 ObjectPool 条目（参考实现同样静默跳过）
    };

    // 分块并行生成，顺序 concat（输出字节序不变）
    let n_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(8)
        .max(1);
    let n = entries.len();
    let chunk = n.div_ceil(n_threads).max(1);
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut b = 0usize;
    while b < n {
        let e = (b + chunk).min(n);
        ranges.push((b, e));
        b = e;
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        for (pi, &(b, e)) in ranges.iter().enumerate() {
            let tx = tx.clone();
            scope.spawn(move || {
                let mut of = String::with_capacity((e - b) * 48);
                for i in b..e {
                    let ent = &entries[i];
                    let off = 0x10 + i * 8;
                    if ent.typ == "obj" {
                        let _ = write!(of, "[pp+{off:#x}] ");
                        describe_into(analyzer, &mut of, ent.value.unwrap_or(0) as u64, 0);
                        of.push('\n');
                    } else if ent.typ == "imm" {
                        let _ = write!(of, "[pp+{off:#x}] {}\n", hex_py(ent.value.unwrap_or(0)));
                    } else {
                        let _ = write!(of, "[pp+{off:#x}] Stub\n");
                    }
                }
                let _ = tx.send((pi, of));
            });
        }
        drop(tx);
    });
    let mut parts: Vec<Option<String>> = (0..ranges.len()).map(|_| None).collect();
    for (pi, s) in rx {
        parts[pi] = Some(s);
    }
    let mut of = String::with_capacity(n * 48);
    of.push_str("pool heap offset: 0x10f000080\n");
    for part in parts.into_iter().flatten() {
        of.push_str(&part);
    }
    let path = out_dir.join("text").join("pp.txt");
    std::fs::write(&path, of).map_err(|e| format!("写 pp.txt 失败: {e}"))?;
    Ok(n)
}

fn write_objs(analyzer: &Analyzer, out_dir: &Path) -> Result<usize, String> {
    // 候选实例：现代系沿用历史基线 176 阈值（与各版本对拍存档一致）；
    // ≤2.14 时代按 profile.alloc.instance_min（2.14=152）
    let imin = if analyzer.profile.format.string_clusters_separate {
        analyzer.profile.alloc.instance_min
    } else {
        176
    };
    let cands: Vec<u64> = analyzer
        .iso
        .instance_fields
        .iter()
        .filter(|(_, (cid, _))| *cid >= imin)
        .map(|(r, _)| *r)
        .collect();
    let n_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(8)
        .max(1);
    let n = cands.len();
    let chunk = n.div_ceil(n_threads).max(1);
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut b = 0usize;
    while b < n {
        let e = (b + chunk).min(n);
        ranges.push((b, e));
        b = e;
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let cands = &cands[..];
    std::thread::scope(|scope| {
        for (pi, &(b, e)) in ranges.iter().enumerate() {
            let tx = tx.clone();
            scope.spawn(move || {
                let mut of = String::with_capacity((e - b) * 96);
                let mut count = 0usize;
                for &ref_ in &cands[b..e] {
                    let cid = analyzer.iso.instance_fields.get(&ref_).unwrap().0;
                    let block = instance_block(analyzer, ref_, cid, 0);
                    if block.starts_with("Obj!") {
                        of.push_str(&block);
                        of.push_str("\n\n");
                        count += 1;
                    }
                }
                let _ = tx.send((pi, of, count));
            });
        }
        drop(tx);
    });
    let mut parts: Vec<Option<(String, usize)>> = (0..ranges.len()).map(|_| None).collect();
    for (pi, s, c) in rx {
        parts[pi] = Some((s, c));
    }
    let mut of = String::with_capacity(n * 96);
    let mut count = 0usize;
    for part in parts.into_iter().flatten() {
        of.push_str(&part.0);
        count += part.1;
    }
    let path = out_dir.join("text").join("objs.txt");
    std::fs::write(&path, of).map_err(|e| format!("写 objs.txt 失败: {e}"))?;
    Ok(count)
}

/// describe_obj（pp.txt 对象描述），贴近 blutter dumpInstance。直接写入 w。
pub fn describe_into(analyzer: &Analyzer, w: &mut String, ref_: u64, depth: usize) {
    let profile = analyzer.profile;
    let cid = analyzer.cid_of_obj(ref_);
    let name = analyzer.sref_str(ref_);
    match cid {
        Some(93) | Some(94) if name.is_some() => {
            let _ = write!(w, "String: \"{}\"", name.unwrap());
            return;
        }
        Some(89) | Some(90) => {
            if let Some((_ta, data)) = analyzer.iso.array_elements.get(&ref_) {
                let _ = write!(w, "List({}) [", data.len());
                for (j, e) in data.iter().enumerate() {
                    if j > 0 {
                        w.push_str(", ");
                    }
                    field_into_or_null(analyzer, w, "ref", *e as i64, 0);
                }
                w.push(']');
                return;
            }
            w.push_str("List");
            return;
        }
        Some(86) | Some(88) => {
            let mcid = cid.unwrap();
            if let Some((_mc, data_ref, _used_ref)) = analyzer.iso.map_data.get(&ref_) {
                if let Some((_ta, data)) = analyzer.iso.array_elements.get(data_ref) {
                    let _ = write!(w, "Map({}) {{", data.len() / 2);
                    let mut j = 0usize;
                    let mut written = 0usize;
                    while j + 1 < data.len() {
                        if written > 0 {
                            w.push_str(", ");
                        }
                        field_into_or_null(analyzer, w, "ref", data[j] as i64, 0);
                        w.push_str(": ");
                        field_into_or_null(analyzer, w, "ref", data[j + 1] as i64, 0);
                        written += 1;
                        j += 2;
                    }
                    w.push('}');
                    return;
                }
            }
            w.push_str(if mcid == 86 { "Map" } else { "Set" });
            return;
        }
        Some(45) => {
            w.push_str("LibraryPrefix");
            return;
        }
        Some(46) => {
            w.push_str("TypeArguments");
            return;
        }
        Some(48) => {
            let _ = write!(w, "Type: {}", name.unwrap_or_default());
            return;
        }
        Some(51) => {
            let _ = write!(w, "TypeParameter: {}", name.unwrap_or_default());
            return;
        }
        Some(60) => {
            let mv = if ref_ <= analyzer.num_base {
                analyzer.vm.mint_values.get(&ref_).copied()
            } else {
                analyzer.iso.mint_values.get(&ref_).copied()
            };
            match mv {
                Some(v) => w.push_str(&hex_py(v)),
                None => w.push_str("int"),
            }
            return;
        }
        Some(61) => {
            w.push_str("double");
            return;
        }
        Some(56) => {
            w.push_str("Closure");
            return;
        }
        Some(7) => {
            let _ = write!(w, "Function: {}", name.unwrap_or_default());
            return;
        }
        Some(18) => {
            w.push_str("Stub");
            return;
        }
        Some(11) => {
            let _ = write!(w, "Field: {}", name.unwrap_or_default());
            return;
        }
        Some(37) => {
            w.push_str("SubtypeTestCache");
            return;
        }
        Some(66) => {
            w.push_str("Record");
            return;
        }
        Some(c) if c >= 176 => {
            w.push_str(&instance_block(analyzer, ref_, c, depth));
            return;
        }
        _ => {}
    }
    if let Some(c) = cid {
        if c < profile.tagging.num_predefined_cids {
            if let Some(n) = profile.class_id_names.get(&c.to_string()) {
                w.push_str(n);
                return;
            }
            w.push('?');
            return;
        }
        let _ = write!(w, "Obj!{}", name.unwrap_or("?"));
        return;
    }
    let _ = write!(w, "Obj!{}", name.unwrap_or("?"));
}

/// field_into + python 语义 `[0] or "Null"`：空输出补 "Null"（describe/递归 list/map 元素处）
fn field_into_or_null(analyzer: &Analyzer, w: &mut String, kind: &str, v: i64, depth: usize) {
    let start = w.len();
    field_into(analyzer, w, kind, v, depth);
    if w.len() == start {
        w.push_str("Null");
    }
}

/// _field_val 的 sink 版：文本写入 w，返回嵌套用户类 cid（无嵌套为 None）。
fn field_into(analyzer: &Analyzer, w: &mut String, kind: &str, v: i64, depth: usize) -> Option<i64> {
    if kind == "unboxed" {
        let u = v as u64;
        if u <= 0x1000_0000_0000_0000 || u >= 0xFFFF_FFFF_FFFF_0000 {
            let _ = write!(w, "int({u:#x})");
        } else {
            let _ = write!(w, "double({})", fmt_double(f64::from_bits(u)));
        }
        return None;
    }
    let v = v as u64;
    let cid = analyzer.cid_of_obj(v);
    let s = analyzer.sref_str(v);
    if matches!(cid, Some(93) | Some(94)) {
        if let Some(s) = s {
            let _ = write!(w, "\"{s}\"");
            return None;
        }
        // 无字符串内容但 cid 是字符串类：走下方通用 ref 输出（参考实现即如此）
    }
    if matches!(cid, Some(89) | Some(90)) {
        if let Some((_ta, data)) = analyzer.iso.array_elements.get(&v) {
            let _ = write!(w, "List({}) [", data.len());
            for (j, e) in data.iter().enumerate() {
                if j > 0 {
                    w.push_str(", ");
                }
                field_into_or_null(analyzer, w, "ref", *e as i64, depth + 1);
            }
            w.push(']');
            return None;
        }
        w.push_str("List");
        return None;
    }
    if cid == Some(60) {
        let mv = if v <= analyzer.num_base {
            analyzer.vm.mint_values.get(&v).copied()
        } else {
            analyzer.iso.mint_values.get(&v).copied()
        };
        match mv {
            Some(mv) => w.push_str(&hex_py(mv)),
            None => w.push_str("int"),
        }
        return None;
    }
    if cid == Some(61) {
        w.push_str("double");
        return None;
    }
    if matches!(cid, Some(86) | Some(88)) {
        if let Some((_mc, data_ref, _used_ref)) = analyzer.iso.map_data.get(&v) {
            if let Some((_ta, data)) = analyzer.iso.array_elements.get(data_ref) {
                let n = data.len() / 2;
                let mut written = 0usize;
                let _ = write!(w, "Map({n}) {{");
                let mut j = 0usize;
                while j + 1 < data.len() && j < n * 2 {
                    if written > 0 {
                        w.push_str(", ");
                    }
                    field_into_or_null(analyzer, w, "ref", data[j] as i64, depth + 1);
                    w.push_str(": ");
                    field_into_or_null(analyzer, w, "ref", data[j + 1] as i64, depth + 1);
                    written += 1;
                    j += 2;
                }
                if written == 0 {
                    // 修正开头 "Map(n) {" 为 "Map(0) { }"（对齐 python 的 pairs 空分支）
                    w.truncate(w.len() - format!("Map({n}) {{").len());
                    w.push_str("Map(0) { }");
                } else {
                    w.push('}');
                }
                return None;
            }
        }
        w.push_str("Map");
        return None;
    }
    if let Some(c) = cid {
        if c >= 176 {
            let _ = write!(
                w,
                "Obj!{}@{}",
                analyzer
                    .cname_by_cid
                    .get(&(c as i64))
                    .map(|s| s.as_str())
                    .unwrap_or("?"),
                hex_noprefix(v as i64)
            );
            return Some(c as i64);
        }
    }
    if let Some(s) = s {
        let _ = write!(w, "\"{s}\"");
        return None;
    }
    if v == 0 || v == 1 {
        return None; // null：不写任何内容，由调用方决定 "Null"/跳过
    }
    if v == 11 {
        w.push_str("false");
        return None;
    }
    if v == 12 {
        w.push_str("true");
        return None;
    }
    w.push_str(&hex_py(v as i64));
    None
}

/// _instance_block：super 链分区 + 递归嵌套的用户类实例 dump（返回完整块文本）。
pub fn instance_block(analyzer: &Analyzer, ref_: u64, cid: u64, depth: usize) -> String {
    let cname = analyzer
        .cname_by_cid
        .get(&(cid as i64))
        .cloned()
        .unwrap_or_else(|| "?".into());
    if depth > 5 {
        return format!("Obj!{cname}@{}", hex_noprefix(ref_ as i64));
    }
    let fields: Vec<&FieldVal> = analyzer
        .iso
        .instance_fields
        .get(&ref_)
        .map(|(_, vals)| vals.iter().collect())
        .unwrap_or_default();

    // 父类链：直接父类 → 祖类 → … → 44
    let mut chain = vec![cid];
    let mut p = analyzer.parent_of.get(&(cid as i64)).copied().unwrap_or(0) as u64;
    let mut seen: std::collections::BTreeSet<u64> = chain.iter().copied().collect();
    while p != 0 && p != 44 && seen.insert(p) {
        chain.push(p);
        p = analyzer.parent_of.get(&(p as i64)).copied().unwrap_or(0) as u64;
    }
    // 从 topmost 祖先开始
    let emit: Vec<u64> = chain.iter().rev().copied().collect();
    let mut body: Vec<String> = Vec::new();
    let mut start_word: i64 = 1;
    for (idx, cc) in emit.iter().enumerate() {
        let end_word = analyzer.nfo_by_cid.get(&(*cc as i64)).copied().unwrap_or(0);
        let is_ancestor = idx != emit.len() - 1;
        let pad = if is_ancestor { "    " } else { "  " };
        let mut seg: Vec<String> = Vec::new();
        for f in &fields {
            let w = f.slot() + 1;
            if !(start_word <= w && w < end_word) {
                continue;
            }
            let off = w * 8;
            let (kind, v, _) = f.as_parts();
            let mut vs = String::new();
            let nested_cid = field_into(analyzer, &mut vs, kind, v, depth + 1);
            if vs.is_empty() {
                continue; // null
            }
            let h = hex_noprefix(off as i64);
            if let Some(nc) = nested_cid {
                let inner =
                    instance_block(analyzer, v as u64, nc as u64, depth + 1).replace('\n', &format!("\n{pad}"));
                seg.push(format!("{pad}off_{h}_{inner}"));
            } else {
                seg.push(format!("{pad}off_{h}: {vs}"));
            }
        }
        if is_ancestor {
            if !seg.is_empty() {
                let anc = analyzer
                    .cname_by_cid
                    .get(&(*cc as i64))
                    .cloned()
                    .unwrap_or_else(|| "?".into());
                body.push(format!("  Super!{anc} : {{\n{}\n  }}", seg.join(",\n")));
            }
        } else {
            body.extend(seg);
        }
        start_word = end_word;
    }
    if body.is_empty() {
        return format!("Obj!{cname}@{}", hex_noprefix(ref_ as i64));
    }
    format!(
        "Obj!{cname}@{} : {{\n{}\n}}",
        hex_noprefix(ref_ as i64),
        body.join(",\n")
    )
}

fn hex_noprefix(v: i64) -> String {
    if v < 0 {
        format!("-{:x}", -v)
    } else {
        format!("{:x}", v)
    }
}

/// 贴近 Python float repr 的双精度格式化：整数值得带 .0，科学计数带符号与两位指数
fn fmt_double(f: f64) -> String {
    if !f.is_finite() {
        return if f.is_nan() {
            "nan".to_string()
        } else if f > 0.0 {
            "inf".to_string()
        } else {
            "-inf".to_string()
        };
    }
    if f == 0.0 {
        return "0.0".to_string();
    }
    let a = f.abs();
    if f.fract() == 0.0 && a < 1e16 {
        return format!("{f:.1}"); // Display 给 "1"，补 ".0"
    }
    if a >= 1e16 || a < 1e-4 {
        // python repr 的科学计数：尾数 + e±NN
        let s = format!("{f:e}");
        let (mant, exp) = match s.split_once('e') {
            Some(v) => v,
            None => (s.as_str(), "0"),
        };
        let e: i32 = exp.parse().unwrap_or(0);
        let mant = if e == 0 && !mant.contains('.') {
            format!("{mant}.0")
        } else {
            mant.to_string()
        };
        return format!("{mant}e{e:+03}");
    }
    format!("{f}")
}

// FieldVal 的便捷解包（slot/kind/value）
impl FieldVal {
    pub fn slot(&self) -> i64 {
        match self {
            FieldVal::Unboxed { slot, .. } | FieldVal::Ref { slot, .. } => *slot,
        }
    }
    pub fn as_parts(&self) -> (&'static str, i64, i64) {
        match self {
            FieldVal::Unboxed { v, slot } => ("unboxed", *v as i64, *slot),
            FieldVal::Ref { v, slot } => ("ref", *v as i64, *slot),
        }
    }
}