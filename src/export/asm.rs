//! DartDumper::DumpCode —— capstone 反汇编 + 最小 IL 伪指令注释。
//! IL 规则与参考实现 dart_aot_export.py 的 _il_pass 逐条一致；
//! 寄存器角色（THR/PP/NULL/sp…）、thread_field_table 偏移、Array::data 偏移
//! 全部从 Profile 取值（不再硬编码 0x60/0x17/x26 等）。

use crate::analyzer::{Analyzer, LibGroups};
use capstone::arch;
use capstone::prelude::*;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;

#[derive(Clone)]
struct Ins {
    addr: u64,
    mnem: String,
    ops: String,
}

pub fn write(analyzer: &Analyzer, libs: &LibGroups, out_dir: &Path) -> Result<usize, String> {
    let asm_dir = out_dir.join("asm");
    std::fs::create_dir_all(&asm_dir).map_err(|e| format!("创建 asm 目录失败: {e}"))?;

    let acc_build = std::time::Duration::ZERO;
    let t0 = std::time::Instant::now();

    // ---------- 阶段 A（串行）：去重决策 + 预分配计划 ----------
    // 全局 seen 必须按函数 ref 升序的全局顺序 claim（影响导出归属的字节级语义）
    struct Plan {
        mangled: String,
        ep: u64,
        csize: u64,
        payload: u64,
        foff: u64,
    }
    struct Job {
        path: std::path::PathBuf,
        header: String,
        plan: Vec<Plan>,
        est: usize,
    }
    let mut jobs: Vec<Job> = Vec::new();
    let mut total = 0usize;
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut used_files: HashMap<String, u32> = HashMap::new();
    for (lib_name, cls_map) in libs {
        let mut base = if lib_name.is_empty() {
            ".dart".to_string()
        } else {
            lib_name.clone()
        }
        .replace('/', "$");
        if !base.ends_with(".dart") {
            base.push_str(".dart");
        }
        let k = base.to_lowercase();
        let fn_name = match used_files.get(&k) {
            Some(&n) => {
                used_files.insert(k.clone(), n + 1);
                format!("{}_{}.dart", &base[..base.len() - 5], n + 1)
            }
            None => {
                used_files.insert(k, 1);
                base.clone()
            }
        };
        let header = format!("// lib: , url: {lib_name}\n\n");
        let mut plan: Vec<Plan> = Vec::new();
        let mut est: usize = header.len();
        for (_cls_name, funcs) in cls_map {
            for f in funcs {
                if f.ep == 0 || !seen.insert(f.ep) {
                    continue;
                }
                let csize = analyzer.code_size(f.idx);
                if csize == 0 {
                    continue;
                }
                let payload = analyzer.instr_base + analyzer.pc_offsets[f.idx];
                let foff = payload + analyzer.slice_off;
                if foff as usize + csize as usize > analyzer.data.len() {
                    continue;
                }
                est += 96 + f.mangled.len() + csize as usize * 12;
                plan.push(Plan {
                    mangled: f.mangled.clone(),
                    ep: f.ep,
                    csize,
                    payload,
                    foff,
                });
            }
        }
        total += plan.len();
        jobs.push(Job { path: asm_dir.join(fn_name), header, plan, est });
    }
    let acc_plan = t0.elapsed() - acc_build;

    // ---------- 阶段 B（并行）：反汇编 + 格式化 + 写文件 ----------
    let n_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(8)
        .max(1);
    let next = std::sync::atomic::AtomicUsize::new(0);
    let err: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
    let t0 = std::time::Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..n_threads {
            scope.spawn(|| {
                let cs = Capstone::new()
                    .arm64()
                    .mode(arch::arm64::ArchMode::Arm)
                    .detail(true)
                    .build()
                    .map_err(|e| format!("capstone 初始化失败: {e}"));
                let cs = match cs {
                    Ok(c) => c,
                    Err(e) => {
                        *err.lock().unwrap() = Some(e);
                        return;
                    }
                };
                loop {
                    if err.lock().unwrap().is_some() {
                        break;
                    }
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if i >= jobs.len() {
                        break;
                    }
                    let job = &jobs[i];
                    let mut of = String::with_capacity(job.est);
                    of.push_str(&job.header);
                    for p in &job.plan {
                        let code =
                            &analyzer.data[p.foff as usize..(p.foff + p.csize) as usize];
                        let insns_all = match cs.disasm_all(code, p.payload) {
                            Ok(v) => v,
                            Err(e) => {
                                *err.lock().unwrap() =
                                    Some(format!("capstone 反汇编失败: {e}"));
                                return;
                            }
                        };
                        let insns: Vec<Ins> = insns_all
                            .iter()
                            .map(|i| {
                                let mnem = i.mnemonic().unwrap_or("").to_string();
                                let ops = normalize_branch_ops(&mnem, i.op_str().unwrap_or(""));
                                Ins { addr: i.address(), mnem, ops }
                            })
                            .collect();
                        let _ = write!(of, "\n  {}() {{\n", p.mangled);
                        let _ = write!(of, "    // ** addr: 0x{:x}, size: 0x{:x}\n", p.ep, p.csize);
                        for (il, grp) in il_pass(analyzer, &insns) {
                            if !il.is_empty() {
                                let _ = write!(of, "    // 0x{:x}: {}\n", grp[0].addr, il);
                            }
                            for insn in grp {
                                let _ = write!(
                                    of,
                                    "    //     0x{:x}: {:<12} {}\n",
                                    insn.addr, insn.mnem, rewrite_ops(analyzer, &insn.ops)
                                );
                            }
                        }
                        of.push_str("  }\n");
                    }
                    if let Err(e) = std::fs::write(&job.path, of) {
                        *err.lock().unwrap() =
                            Some(format!("写 {} 失败: {e}", job.path.display()));
                        return;
                    }
                }
            });
        }
    });
    let acc_parallel = t0.elapsed();
    if let Some(e) = err.into_inner().unwrap() {
        return Err(e);
    }
    if std::env::var("DART_AOT_TIMINGS").is_ok() {
        eprintln!(
            "[timing]   asm内: build={:?} 决策={:?} 并行(disasm+format+写)={:?} ({n_threads}线程)",
            acc_build, acc_plan, acc_parallel
        );
    }
    Ok(total)
}

// ---------------------------------------------------------------- 工具

/// `\w+` 首词
fn first_word(s: &str) -> Option<&str> {
    let end = s
        .char_indices()
        .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_'))
        .map(|(i, _)| i)
        .unwrap_or(s.len());
    if end == 0 {
        None
    } else {
        Some(&s[..end])
    }
}

/// 解析 r"(\w+), \[(\w+), #(-?0x[0-9a-f]+|-?\d+)" 前缀 → (dst, base, disp)
fn parse_mem(ops: &str) -> Option<(String, String, String)> {
    let (dst, rest) = ops.split_once(", [")?;
    let dst = first_word(dst)?.to_string();
    let (base, tail) = rest.split_once(", #")?;
    let base = first_word(base)?.to_string();
    let disp = scan_disp(tail)?;
    Some((dst, base, disp.to_string()))
}

/// 从串首扫描 -?0x[hex]+|-?digits
fn scan_disp(s: &str) -> Option<&str> {
    let b = s.as_bytes();
    if b.is_empty() {
        return None;
    }
    let mut i = 0usize;
    if b[0] == b'-' {
        i = 1;
        if i >= b.len() {
            return None;
        }
    }
    if b.get(i..i + 2) == Some(b"0x") || b.get(i..i + 2) == Some(b"0X") {
        i += 2;
        let start = i;
        while i < b.len() && b[i].is_ascii_hexdigit() {
            i += 1;
        }
        if i == start {
            return None;
        }
        return Some(&s[0..i]);
    }
    let start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == start {
        return None;
    }
    Some(&s[0..i])
}

/// python int(disp, 0) 语义
fn disp_int(disp: &str) -> i64 {
    let neg = disp.starts_with('-');
    let d = disp.trim_start_matches('-');
    let v = if let Some(h) = d.strip_prefix("0x").or_else(|| d.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).unwrap_or(0)
    } else {
        d.parse::<i64>().unwrap_or(0)
    };
    if neg {
        -v
    } else {
        v
    }
}

/// `#(0x[0-9a-f]+|\d+)` 第一次出现（re.search 语义）
fn find_imm(ops: &str) -> Option<String> {
    let p = ops.find('#')?;
    let tail = &ops[p + 1..];
    let disp = scan_disp(tail)?;
    Some(disp.to_string())
}

/// x29→fp、x26→THR 等（对齐 _dart_regname / DART_REG_ALIAS）
fn dart_regname(analyzer: &Analyzer, name: &str) -> String {
    if let Some(a) = analyzer.platform.register_aliases.get(name) {
        return a.clone();
    }
    if let Some(num) = name.strip_prefix(['x', 'w']) {
        if !num.is_empty() && num.chars().all(|c| c.is_ascii_digit()) {
            return format!("r{num}");
        }
    }
    name.to_string()
}

/// capstone 5 的分支立即数带 '#'，capstone 6（python 参考实现所用）不带。
/// 仅对分支类指令去掉目标地址的 '#'，其余立即数（ldr #0x17、tbz 的 #0 等）保持。
fn normalize_branch_ops(mnem: &str, ops: &str) -> String {
    let is_branch = matches!(mnem, "b" | "bl")
        || mnem.starts_with("b.")
        || matches!(mnem, "tbz" | "tbnz" | "cbz" | "cbnz");
    if !is_branch {
        return ops.to_string();
    }
    if ops.starts_with("#0x") {
        return ops[1..].to_string();
    }
    if mnem == "bl" && ops.starts_with('#') {
        return ops[1..].to_string();
    }
    if matches!(mnem, "tbz" | "tbnz" | "cbz" | "cbnz") {
        if let Some((head, tail)) = ops.rsplit_once(", #") {
            if tail.starts_with("0x") {
                return format!("{head}, {tail}");
            }
        }
    }
    ops.to_string()
}

/// 等价 python re.sub(r"\b(x|w)(\d+|zr)\b", repl, ops)
fn rewrite_ops(analyzer: &Analyzer, ops: &str) -> String {
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let chars: Vec<char> = ops.chars().collect();
    let mut out = String::with_capacity(ops.len());
    let mut i = 0usize;
    let n = chars.len();
    while i < n {
        if (chars[i] == 'x' || chars[i] == 'w')
            && (i == 0 || !is_word(chars[i - 1]))
            && i + 1 < n
        {
            // zr 分支
            if chars[i + 1] == 'z' && i + 2 < n && chars[i + 2] == 'r' && (i + 3 >= n || !is_word(chars[i + 3])) {
                let reg = format!("{}zr", chars[i]);
                out.push_str(&dart_regname(analyzer, &reg));
                i += 3;
                continue;
            }
            // digits 分支
            if chars[i + 1].is_ascii_digit() {
                let mut k = i + 1;
                while k < n && chars[k].is_ascii_digit() {
                    k += 1;
                }
                if k >= n || !is_word(chars[k]) {
                    let reg: String = chars[i..k].iter().collect();
                    out.push_str(&dart_regname(analyzer, &reg));
                    i = k;
                    continue;
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

// ---------------------------------------------------------------- IL

/// 平台角色寄存器
struct Roles {
    thr: String,
    pp: String,
    null: String,
    barrier: String,
    sp: String,
    fp: String,
    lr: String,
    array_data_minus_tag: i64,
    non_field: std::collections::HashSet<String>,
}

fn roles(analyzer: &Analyzer) -> Roles {
    let g = |k: &str, d: &str| {
        analyzer
            .platform
            .registers
            .get(k)
            .cloned()
            .unwrap_or_else(|| d.into())
    };
    let thr = g("thr", "x26");
    Roles {
        thr,
        pp: g("pp", "x27"),
        null: g("null", "x22"),
        barrier: g("barrier", "x16"),
        sp: g("sp", "x15"),
        fp: g("fp", "x29"),
        lr: g("lr", "x30"),
        array_data_minus_tag: analyzer.profile.offset("array_data_minus_tag") as i64,
        non_field: analyzer.platform.non_field_base.iter().cloned().collect(),
    }
}

/// 最小 IL 分组（字符串匹配，规避 capstone 寄存器 ID 差异）。
fn il_pass(analyzer: &Analyzer, insns: &[Ins]) -> Vec<(String, Vec<Ins>)> {
    let rl = roles(analyzer);
    let mut out: Vec<(String, Vec<Ins>)> = Vec::new();
    let mut i = 0usize;
    let n = insns.len();
    let pp = rl.pp.clone();
    while i < n {
        let ins = &insns[i];
        let mnem = ins.mnem.as_str();
        let ops = ins.ops.as_str();

        // EnterFrame: stp fp, lr, [... , #-0x10]! + mov fp, SP
        if mnem == "stp" && ops.contains(&rl.fp) && ops.contains(&rl.lr) && ops.contains("#-0x10")
        {
            let mut grp = vec![ins.clone()];
            i += 1;
            if i < n && insns[i].mnem == "mov" && insns[i].ops.starts_with(&rl.fp) {
                grp.push(insns[i].clone());
                i += 1;
            }
            out.push(("EnterFrame".to_string(), grp));
            continue;
        }
        // AllocStack: sub sp, sp, #imm
        if mnem == "sub" && ops.starts_with(&format!("{}, {}", rl.sp, rl.sp)) {
            let imm = find_imm(ops);
            let grp = vec![ins.clone()];
            i += 1;
            out.push((
                imm.map(|v| format!("AllocStack({v})")).unwrap_or_default(),
                grp,
            ));
            continue;
        }
        // CheckStackOverflow: ldr barrier, [thr, #off] + cmp + b.cond
        if mnem == "ldr" && ops.contains(&format!("{}, [{}", rl.barrier, rl.thr)) {
            let mut grp = vec![ins.clone()];
            i += 1;
            if i < n && insns[i].mnem == "cmp" && insns[i].ops.contains(&rl.sp) {
                grp.push(insns[i].clone());
                i += 1;
                if i < n
                    && insns[i].mnem.starts_with("b.")
                    && !insns[i].mnem.starts_with("bl")
                {
                    grp.push(insns[i].clone());
                    i += 1;
                }
            }
            out.push(("CheckStackOverflow".to_string(), grp));
            continue;
        }
        // Move: mov rN, rM（寄存器间；ops 恰为两个词）
        if mnem == "mov" {
            if let Some((a, b)) = ops.split_once(", ") {
                if !a.is_empty()
                    && !a.contains(' ')
                    && !b.contains(',')
                    && !b.contains(' ')
                    && (b.starts_with('x') || b.starts_with('w'))
                {
                    let grp = vec![ins.clone()];
                    i += 1;
                    out.push((
                        format!(
                            "{} = {}",
                            dart_regname(analyzer, a),
                            dart_regname(analyzer, b)
                        ),
                        grp,
                    ));
                    continue;
                }
            }
        }
        // LeaveFrame: ldp fp, lr, [SP], #imm
        if mnem == "ldp" && ops.contains(&rl.fp) && ops.contains(&rl.lr) {
            let grp = vec![ins.clone()];
            i += 1;
            out.push(("LeaveFrame".to_string(), grp));
            continue;
        }
        // Return: ret
        if mnem == "ret" {
            let grp = vec![ins.clone()];
            i += 1;
            out.push(("ret".to_string(), grp));
            continue;
        }
        // Branch: b / b.cond
        if mnem.starts_with('b') && !matches!(mnem, "bl" | "blr" | "br") {
            let grp = vec![ins.clone()];
            i += 1;
            out.push((
                if ops.is_empty() {
                    mnem.to_string()
                } else {
                    format!("{mnem} {ops}")
                },
                grp,
            ));
            continue;
        }
        // StaticCall: bl <addr>
        if mnem == "bl" {
            let mm = first_word(ops).filter(|w| w.starts_with("0x"));
            let tgt = mm
                .and_then(|w| i64::from_str_radix(&w[2..], 16).ok())
                .unwrap_or(0) as u64;
            let grp = vec![ins.clone()];
            i += 1;
            if mm.is_some() {
                let nm = analyzer.name_by_ep.get(&tgt);
                out.push((
                    nm.map(|nm| format!("r0 = {nm}()"))
                        .unwrap_or_else(|| format!("r0 = call {:#x}", tgt)),
                    grp,
                ));
            } else {
                out.push((String::new(), grp));
            }
            continue;
        }
        // InstanceCall / ClosureCall: blr
        if mnem == "blr" {
            let grp = vec![ins.clone()];
            i += 1;
            out.push(("r0 = [R]()".to_string(), grp));
            continue;
        }
        // LoadClassId: ldur rX, [obj, #-1] + ubfx
        if mnem == "ldur" && ops.ends_with(", #-1]") {
            if let Some((_dst, base, disp)) = parse_mem(ops) {
                if disp == "-1"
                    && i + 1 < n
                    && insns[i + 1].mnem == "ubfx"
                    && insns[i + 1]
                        .ops
                        .contains(&format!("#0x{:x}", analyzer.profile.tagging.cid_tag_pos))
                    && insns[i + 1].ops.contains(&format!(
                        "#0x{:x}",
                        (analyzer.profile.tagging.cid_tag_mask + 1).ilog2()
                    ))
                {
                    let grp = vec![ins.clone(), insns[i + 1].clone()];
                    let dst = first_word(&insns[i + 1].ops).unwrap_or("");
                    i += 2;
                    out.push((
                        format!(
                            "{} = LoadClassIdInstr({})",
                            dart_regname(analyzer, dst),
                            dart_regname(analyzer, &base)
                        ),
                        grp,
                    ));
                    continue;
                }
            }
        }
        // CheckNull: cmp rN, NULL + b.cond
        if mnem == "cmp" && ops.contains(&rl.null) {
            let mut grp = vec![ins.clone()];
            i += 1;
            if i < n && insns[i].mnem.starts_with("b.") {
                grp.push(insns[i].clone());
                i += 1;
            }
            out.push(("CheckNull".to_string(), grp));
            continue;
        }
        // LoadStaticField: ldr xN, [thr_table_off] + ldr xM, [xN, #off]
        if mnem == "ldr" {
            let pat = format!(", [{}, #0x{:x}]", rl.thr, profile_thr_table(analyzer));
            if ops.contains(&pat) {
                let dst0 = first_word(ops).map(|w| w.to_string());
                if let Some(dst0) = dst0 {
                    if i + 1 < n && insns[i + 1].mnem == "ldr" {
                        if let Some((dst2, base2, disp2)) = parse_mem(&insns[i + 1].ops) {
                            if base2 == dst0 && (disp2.starts_with("0x") || disp2.starts_with("-0x"))
                            {
                                let foff = disp_int(&disp2) >> 1;
                                let grp = vec![ins.clone(), insns[i + 1].clone()];
                                i += 2;
                                out.push((
                                    format!(
                                        "{} = LoadStaticField(0x{:x})",
                                        dart_regname(analyzer, &dst2),
                                        foff
                                    ),
                                    grp,
                                ));
                                continue;
                            }
                        }
                    }
                }
            }
        }
        // branchIfSmi: tbz wN, #0, addr
        if mnem == "tbz" && ops.contains("#0") {
            if let Some((dst, rest)) = ops.split_once(", #0, ") {
                let dst = first_word(dst).unwrap_or(dst);
                if !dst.is_empty() && rest.starts_with("0x") {
                    let grp = vec![ins.clone()];
                    i += 1;
                    out.push((
                        format!(
                            "branchIfSmi({}, {})",
                            dart_regname(analyzer, dst),
                            rest.trim()
                        ),
                        grp,
                    ));
                    continue;
                }
            }
        }
        // 对象池/静态字段大偏移：add rM, PP, #imm, lsl #12 → ldr/str rN, [rM, #disp]
        if mnem == "add" {
            if let Some(pm) = parse_pp_add(ops, &pp) {
                if i + 1 < n
                    && matches!(insns[i + 1].mnem.as_str(), "ldr" | "ldur" | "str" | "stur")
                {
                    if let Some((rn, base, disp)) = parse_mem(&insns[i + 1].ops) {
                        if base == pm.0 {
                            let off = pm.1 as i64 + disp_int(&disp);
                            let m2 = insns[i + 1].mnem.as_str();
                            let grp = vec![ins.clone(), insns[i + 1].clone()];
                            i += 2;
                            if m2 == "ldr" || m2 == "ldur" {
                                out.push((
                                    format!("{} = pp[0x{:x}]", dart_regname(analyzer, &rn), off),
                                    grp,
                                ));
                            } else {
                                out.push((
                                    format!("pp[0x{:x}] = {}", off, dart_regname(analyzer, &rn)),
                                    grp,
                                ));
                            }
                            continue;
                        }
                    }
                }
            }
        }
        // LoadField / ArrayLoad / pp load
        if mnem == "ldr" || mnem == "ldur" {
            if let Some((rn, base, disp)) = parse_mem(ops) {
                let di = disp_int(&disp);
                if base == pp {
                    let grp = vec![ins.clone()];
                    i += 1;
                    out.push((
                        format!("{} = pp[0x{:x}]", dart_regname(analyzer, &rn), di),
                        grp,
                    ));
                    continue;
                }
                if !rl.non_field.contains(&base) && di == rl.array_data_minus_tag {
                    let grp = vec![ins.clone()];
                    i += 1;
                    out.push((
                        format!(
                            "ArrayLoad: {} = {}[0]  ; List_8",
                            dart_regname(analyzer, &rn),
                            dart_regname(analyzer, &base)
                        ),
                        grp,
                    ));
                    continue;
                }
                if !rl.non_field.contains(&base) && di >= 0 {
                    let grp = vec![ins.clone()];
                    i += 1;
                    out.push((
                        format!(
                            "LoadField: {} = {}->field_{:x}",
                            dart_regname(analyzer, &rn),
                            dart_regname(analyzer, &base),
                            di
                        ),
                        grp,
                    ));
                    continue;
                }
            }
        }
        // StoreField / ArrayStore / pp store
        if mnem == "str" || mnem == "stur" {
            if let Some((rn, base, disp)) = parse_mem(ops) {
                let di = disp_int(&disp);
                if base == pp {
                    let grp = vec![ins.clone()];
                    i += 1;
                    out.push((
                        format!("pp[0x{:x}] = {}", di, dart_regname(analyzer, &rn)),
                        grp,
                    ));
                    continue;
                }
                if !rl.non_field.contains(&base) && di == rl.array_data_minus_tag {
                    let grp = vec![ins.clone()];
                    i += 1;
                    out.push((
                        format!(
                            "ArrayStore: {}[0] = {}  ; List_8",
                            dart_regname(analyzer, &base),
                            dart_regname(analyzer, &rn)
                        ),
                        grp,
                    ));
                    continue;
                }
                if !rl.non_field.contains(&base) && di >= 0 {
                    let grp = vec![ins.clone()];
                    i += 1;
                    out.push((
                        format!(
                            "StoreField: {}->field_{:x} = {}",
                            dart_regname(analyzer, &base),
                            di,
                            dart_regname(analyzer, &rn)
                        ),
                        grp,
                    ));
                    continue;
                }
            }
        }
        let grp = vec![ins.clone()];
        i += 1;
        out.push((String::new(), grp));
    }
    out
}

fn profile_thr_table(analyzer: &Analyzer) -> u64 {
    analyzer.profile.offset("thread_field_table_values")
}

/// 解析 r"(\w+), PP, #(0x[0-9a-f]+|\d+), lsl #(?:12|0xc)" → (dst, big)
fn parse_pp_add(ops: &str, pp: &str) -> Option<(String, u64)> {
    let (dst, rest) = ops.split_once(", ")?;
    let dst = first_word(dst)?.to_string();
    let rest = rest.strip_prefix(pp)?;
    let rest = rest.strip_prefix(", #")?;
    let (big, rest) = rest.split_once(", lsl")?;
    let big = scan_disp(big)?;
    let bigv = disp_int(big);
    let rest = rest.trim_start_matches(' ');
    let rest = rest.strip_prefix('#')?;
    if rest == "12" || rest == "0xc" {
        Some((dst, bigv as u64))
    } else {
        None
    }
}