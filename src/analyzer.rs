//! 高层编排（对应参考实现 dart_aot_export.py 的 Analyzer 类）：
//! 容器 → VM/ISO 快照 → fill → 三级归属与命名 → 指令表 → 函数列表。
//!
//! 所有命名/地址逻辑与 Python 参考实现逐条一致；唯一差别是输出结构用
//! BTreeMap（Python dict 插入序 = ref 升序，BTreeMap 迭代序等价确定）。

use crate::engine::fill::fill_snapshot;
use crate::engine::restore::{
    func_blutter_kind, get_function_name_4_ida, library_name, scrub_name,
};
use crate::engine::snapshot::{ClassRec, FieldRec, FieldVal, Snapshot};
use crate::platform::{load_container, locate_snapshots, ContainerInfo};
use crate::profile::{PlatformProfile, SdkProfile};
use std::collections::BTreeMap;

/// build_functions 的产物：library → class → 函数组（r2/asm 共享，一次构建）
pub type LibGroups = Vec<(String, Vec<(String, Vec<FuncEntry>)>)>;

/// 一条带地址的具名函数（build_functions 的单元）
#[derive(Debug, Clone)]
pub struct FuncEntry {
    pub ep: u64,
    pub lib: String,
    pub cls: String,
    pub mangled: String,
    pub idx: usize,
}


/// DART_AOT_TIMINGS=1 时打印阶段耗时（性能调优辅助）
#[inline]
fn t(name: &str, since: &mut std::time::Instant) {
    if std::env::var("DART_AOT_TIMINGS").is_ok() {
        let now = std::time::Instant::now();
        eprintln!("[timing] {name}: {:?}", now.duration_since(*since));
        *since = now;
    }
}

pub struct Analyzer<'a> {
    pub data: &'a [u8],
    pub profile: &'a SdkProfile,
    pub platform: &'a PlatformProfile,
    pub container: ContainerInfo,
    pub slice_off: u64,
    pub vm: Snapshot<'a>,
    pub iso: Snapshot<'a>,
    pub first_entry: u64,
    pub pc_offsets: Vec<u64>,
    /// code_text_offsets 源：函数 code_index 为绝对 ref，需减去 Code 簇起始 ref
    /// 才是 pc_offsets 下标；rodata 源恒为 0（code_index 本身即表空间编号-1）
    pub code_base_ref: u64,
    /// 指令段基址（file-offset 空间 = 符号文件偏移 - slice_off，与参考实现一致）
    pub instr_base: u64,
    pub num_base: u64,
    pub cname_by_cid: BTreeMap<i64, String>,
    pub parent_of: BTreeMap<i64, i64>,
    pub nfo_by_cid: BTreeMap<i64, i64>,
    pub name_by_ep: BTreeMap<u64, String>,
    pub payload_infos: Vec<u64>,
    /// ELF 函数符号 {地址 → 符号名}：过渡版（2.16/2.18）函数名不在 fill ref 时按地址回填
    pub elf_names: BTreeMap<u64, String>,
    /// 函数 ref → (entry, pc 索引)，new() 里一次算好（name_by_ep/build_functions/导出共享）
    pub func_eps: BTreeMap<u64, (u64, usize)>,
    /// 解析期告警（drift/alloc mismatch 等）
    pub warnings: Vec<String>,
    /// Field 簇恢复出的实例字段（AOT 只保留少量具名字段，见 docs/DECOMPILER.md）
    pub fields_rec: Vec<RecoveredField>,
    /// (类名, 字节偏移) → 字段名。只收「实例字段」——字索引落在 owner 类
    /// nfo 区间内的那些；static 字段存的是 field_id（不在区间内），不入表。
    pub field_by_class_off: BTreeMap<(String, u64), String>,
}

/// 具名字段的一行（CLI `dae fields` 与 `text/fields.txt` 共用同一份形状）。
pub struct FieldRow {
    pub class: String,
    pub name: String,
    /// "rec" = Field 簇直接写着；"accessor" = 隐式 getter/setter 名推断
    pub source: &'static str,
    pub off: u64,
}

/// Field 簇里的一条具名字段记录。
///
/// AOT 会丢掉绝大多数 Field 对象（`Precompiler::DropFields` 只在非 PRODUCT 构建
/// 保留字段名），真机产物里通常只剩几十条（`@pragma("vm:entry-point")` 那些）。
/// snapshot 里 Field 的 `host_offset_or_field_id` 是 **Smi**，而 Smis 被并进 Mint
/// 簇（app_snapshot.cc: `Trace`："Smis are merged into the Mint cluster"），
/// 所以 Mint 值 = 字索引：首字段在字 1（泛型类因类型参数槽在字 2），
/// 字节偏移 = 字索引 × word_size；机器码里的位移 = 字节偏移 − 1（tagged 折算）。
#[derive(Debug, Clone)]
pub struct RecoveredField {
    pub class: String,
    pub name: String,
    pub word: i64,
    pub off: u64,
}

impl<'a> Analyzer<'a> {
    pub fn new(
        data: &'a [u8],
        profile: &'a SdkProfile,
        platform: &'a PlatformProfile,
    ) -> Result<Analyzer<'a>, String> {
        let (offsets, used_fallback) = locate_snapshots(data, platform)?;
        Self::new_located(data, profile, platform, offsets, used_fallback)
    }

    /// 快照偏移已由调用方定位（自动识别 probe 复用同一份定位结果）。
    pub fn new_located(
        data: &'a [u8],
        profile: &'a SdkProfile,
        platform: &'a PlatformProfile,
        offsets: (u64, u64, u64),
        used_fallback: bool,
    ) -> Result<Analyzer<'a>, String> {
        let mut since = std::time::Instant::now();
        let mut warnings: Vec<String> = Vec::new();
        let container = load_container(platform, data)?;
        t("container(符号表)", &mut since);
        let (vm_off, iso_off, instr_off) = offsets;
        if used_fallback {
            warnings.push(
                "platform symbols missing; VM/ISO sections located via snapshot-magic fallback; instruction-section addresses unavailable (object-layer export)".to_string(),
            );
        }
        let slice_off = crate::platform::macho::fat_slice_offset(data) as u64;

        let mut vm = if profile.format.single_snapshot {
            Snapshot::stub(profile, data)
        } else {
            Snapshot::parse(profile, data, vm_off as usize, Some(&mut warnings))?
        };
        t("parse vm(外层+alloc)", &mut since);
        let mut iso = Snapshot::parse(profile, data, iso_off as usize, Some(&mut warnings))?;
        t("parse iso(外层+alloc)", &mut since);
        fill_snapshot(profile, &mut vm, Some(&mut warnings))?;
        t("fill vm", &mut since);
        fill_snapshot(profile, &mut iso, Some(&mut warnings))?;
        t("fill iso", &mut since);

        let (first_entry, mut pc_offsets) = iso.decode_instructions_table();
        let mut code_base_ref: u64 = 0;
        if first_entry == 0 && pc_offsets.is_empty() {
            if profile.format.instructions_table_source == "code_text_offsets" {
                if let Some(tos) = iso.text_offsets.clone() {
                    // 该路径的 text-offset 是**增量累加**出来的，个别版本（2.10）的累加
                    // 口径不同，会得到负值（u64 里表现为巨大值）。这种表不能用：
                    // 配上指令段基址会算出"看起来在文件内"的假地址，产物是垃圾而不是报错
                    // （实测 2.10.4：399 843 条语句、38 161 行未映射）。宁可退回对象层。
                    if tos.iter().any(|v| *v > i64::MAX as u64) {
                        warnings.push(
                            "code_text_offsets: the text-offset sequence contains negative values \
                             (this version accumulates differently); function addresses are not \
                             exportable (object layer only: frida/pp/objs)"
                                .to_string(),
                        );
                    } else {
                        pc_offsets = tos;
                        // entry_for 的 idx = ci - code_base_ref - 1，故此处取
                        // code_start_ref - 1 使首个 code 对象（ci=code_start_ref）→ idx 0
                        code_base_ref = iso.code_start_ref.unwrap_or(1).saturating_sub(1);
                    }
                } else {
                    warnings.push("code_text_offsets: the Code cluster produced no text-offset sequence; function addresses unavailable".to_string());
                }
            } else if profile.instr_table_in_image() {
                if profile.format.instructions_table_source == "code_text_offsets_unsupported" {
                    warnings.push("this Dart version (2.10-2.14) uses bare instructions with the legacy Code-cluster layout; function addresses are not exportable (object layer only: frida/pp/objs)".to_string());
                } else {
                    warnings.push("the instruction table is present neither in the snapshot stream header nor captured via Code-cluster text offsets; function addresses/r2/asm not exportable (object layer only: frida/pp/objs)".to_string());
                }
            } else {
                warnings.push("instruction table decoded empty: function addresses unavailable (check that the SDK profile is correct)".to_string());
            }
        }
        t("指令表", &mut since);
        let instr_base = instr_off.saturating_sub(slice_off);
        if std::env::var("DART_AOT_VERBOSE").is_ok() {
            eprintln!(
                "[dbg] vm_off={vm_off:#x} iso_off={iso_off:#x} instr_off={instr_off:#x} slice_off={slice_off:#x} instr_base={instr_base:#x} pc_len={} pc_first={:#x} pc_last={:#x} first_entry={first_entry}",
                pc_offsets.len(),
                pc_offsets.first().copied().unwrap_or(0),
                pc_offsets.last().copied().unwrap_or(0),
            );
        }
        let num_base = iso.hdr.get("num_base_objects");

        // cname_by_cid：iso 先（setdefault → 首见生效），vm 补缺。
        // 分块并行：chunk 内首见语义 + 按块序合并 entry.or_insert，与串行等价。
        let cname_by_cid = {
            let iso_list: Vec<(u64, ClassRec)> = iso.classes.iter().map(|(r, c)| (*r, *c)).collect();
            let vm_list: Vec<(u64, ClassRec)> = vm.classes.iter().map(|(r, c)| (*r, *c)).collect();
            let mut merged: BTreeMap<i64, String> = BTreeMap::new();
            for part in chunked_merge2(&iso_list, &vm_list, num_base, profile, &vm, &iso) {
                for (cid, name) in part {
                    merged.entry(cid).or_insert(name);
                }
            }
            merged
        };

        // 父类链 + nfo：仅 iso classes（同 cid 后见覆盖 → 按块序 merge 时直接 insert）
        let (parent_of, nfo_by_cid) = {
            let iso_list: Vec<(u64, ClassRec)> = iso.classes.iter().map(|(r, c)| (*r, *c)).collect();
            let mut p_merged: BTreeMap<i64, i64> = BTreeMap::new();
            let mut n_merged: BTreeMap<i64, i64> = BTreeMap::new();
            for (pm, nm) in chunked_parent(&iso_list, num_base, &vm, &iso) {
                for (k, v) in pm {
                    p_merged.insert(k, v);
                }
                for (k, v) in nm {
                    n_merged.insert(k, v);
                }
            }
            (p_merged, n_merged)
        };

        t("cname/parent 映射(并行)", &mut since);
        let payload_infos = iso.payload_infos.clone().unwrap_or_default();

        let mut a = Analyzer {
            data,
            profile,
            platform,
            container,
            slice_off,
            vm,
            iso,
            first_entry,
            pc_offsets,
            code_base_ref,
            instr_base,
            num_base,
            cname_by_cid,
            parent_of,
            nfo_by_cid,
            name_by_ep: BTreeMap::new(),
            elf_names: elf_function_names(data),
            payload_infos,
            func_eps: BTreeMap::new(),
            warnings,
            fields_rec: Vec::new(),
            field_by_class_off: BTreeMap::new(),
        };
        a.build_fields();

        t("payload_infos", &mut since);
        a.build_name_by_ep();
        t("name_by_ep", &mut since);
        // ELF 符号回填：入口正确但解析名缺失/为空的过渡版（2.16/2.18 等）按地址补名。
        if a.profile.format.elf_name_backfill {
            if std::env::var("DART_AOT_DEBUG_ELF").is_ok() {
                eprintln!(
                    "[dbg-elf] elf_names={} has_9c2e0={} has_9c2e0addr={}",
                    a.elf_names.len(),
                    a.elf_names.contains_key(&0x9c2e0),
                    a.elf_names.keys().any(|k| (k & 0xfffff) == 0x9c2e0 || *k == 0x9c2e0)
                );
            }
            for (&_, &(ep, _)) in &a.func_eps {
                let existing = a.name_by_ep.get(&ep).map(|s| s.as_str()).unwrap_or("");
                let missing = existing.is_empty()
                    || existing.ends_with("::")
                    || existing.starts_with("lib.");
                if missing {
                    if let Some(sym) = a.elf_names.get(&ep) {
                        let clean = clean_elf_fn(sym);
                        if !clean.is_empty() {
                            a.name_by_ep.insert(ep, clean.clone());
                            if std::env::var("DART_AOT_DEBUG_ELF").is_ok() {
                                eprintln!("[dbg-elf-backfill] {ep:#x} {sym} -> {clean}");
                            }
                        }
                    }
                }
            }
            // 强制回填：func_eps 缺失但 ELF 有符号的地址（2.19.6 main/greet 等函数簇漂移导致
            // code_index 错误 → entry_for 返回 None → 不在 func_eps）。按 ELF 符号地址直接补名。
            let instr_min = a.instr_base;
            let instr_max = instr_min + a.pc_offsets.last().copied().unwrap_or(0) + 0x200;
            for (&ep, sym) in &a.elf_names {
                if ep >= instr_min && ep < instr_max && !a.name_by_ep.contains_key(&ep) {
                    let c = clean_elf_fn(sym);
                    if !c.is_empty() {
                        if std::env::var("DART_AOT_DEBUG_ELF").is_ok() {
                            eprintln!("[dbg-elf-force] {ep:#x} {sym} -> {c}");
                        }
                        a.name_by_ep.insert(ep, c);
                    }
                }
            }
        }
        if std::env::var("DART_AOT_DEBUG_FUNCS").is_ok() {
            for (ep, name) in &a.name_by_ep {
                eprintln!("[dbg-ep] ep={ep:#x} {name}");
            }
            let mut v: Vec<(u64, u64)> = a
                .iso
                .functions
                .iter()
                .map(|(r, f)| (*r, f.name_ref))
                .collect();
            v.sort();
            for (r, nr) in v {
                let name = a.iso.strings.get(&nr).cloned().flatten().unwrap_or_default();
                eprintln!("[dbg-func] ref={r} {name}");
            }
        }
        if std::env::var("DART_AOT_DEBUG_FIELDS").is_ok() {
            eprintln!("[dbg-fields] iso={} vm={} recovered={}",
                a.iso.fields.len(), a.vm.fields.len(), a.fields_rec.len());
            for f in &a.fields_rec {
                eprintln!("[dbg-fields] {} word={} off={:#x} {}", f.class, f.word, f.off, f.name);
            }
        }
        Ok(a)
    }

    /// Field 簇 → 具名字段表。两个来源之一（另一个是访问器名推断，见 decompiler）：
    /// 这是 snapshot 里**直接写着**的字段名，偏移由 Mint 值给出。
    fn build_fields(&mut self) {
        let ws = self.profile.word_size;
        // 两个 isolate 都要看：SDK 字段多在 ISO，静态字段的 owner 在 VM 侧也出现
        let mut items: Vec<(u64, FieldRec)> = Vec::new();
        items.extend(self.vm.fields.iter().map(|(r, f)| (*r, *f)));
        items.extend(self.iso.fields.iter().map(|(r, f)| (*r, *f)));
        for (_, f) in items {
            let Some(cls) = self.class_of(f.owner_ref) else { continue };
            let class = scrub_name(self.sref_str(cls.name_ref));
            if class.is_empty() {
                continue; // 无名的伪类（`::`）：偏移无从对应，丢了不留假名
            }
            let name = scrub_name(self.sref_str(f.name_ref));
            if name.is_empty() {
                continue;
            }
            let mint = if f.offset_or_id <= self.num_base {
                self.vm.mint_values.get(&f.offset_or_id).copied()
            } else {
                self.iso.mint_values.get(&f.offset_or_id).copied()
            };
            let Some(word) = mint else { continue };
            // 字索引必须落在类的字段区（0 = tags 字，>= nfo = 越界）：
            // static 字段存的是 field_id，越界即被挡掉，这正是我们要的甄别
            if word < 1 || cls.next_field_off <= 0 || word >= cls.next_field_off {
                continue;
            }
            let off = word as u64 * ws;
            self.fields_rec.push(RecoveredField { class: class.clone(), name: name.clone(), word, off });
            // 同一 (类,偏移) 出现两个名字（继承链上的遮蔽）时不写：宁可没有，不可写错
            match self.field_by_class_off.get(&(class.clone(), off)) {
                Some(prev) if prev != &name => {
                    self.field_by_class_off.remove(&(class.clone(), off));
                }
                Some(_) => {}
                None => {
                    self.field_by_class_off.insert((class, off), name);
                }
            }
        }
        self.fields_rec.sort_by(|a, b| (a.class.as_str(), a.off).cmp(&(b.class.as_str(), b.off)));
    }

    /// 字段清单（只含 Field 簇的 `rec` 行）。
    pub fn field_rows_basic(&self) -> Vec<FieldRow> {
        let mut rows: Vec<FieldRow> = self
            .fields_rec
            .iter()
            .map(|f| FieldRow { class: f.class.clone(), name: f.name.clone(), source: "rec", off: f.off })
            .collect();
        rows.sort_by(|a, b| (&a.class, a.off).cmp(&(&b.class, b.off)));
        rows
    }

    /// 对外口径的字段清单：`asm` 特性下带上访问器名推断（`accessor`），否则只有记录行。
    /// 推断失败（无 capstone / 反汇编初始化失败）时退回记录行，不报错也不编造。
    pub fn field_rows(&self) -> Vec<FieldRow> {
        #[cfg(feature = "asm")]
        {
            if let Ok(rec) = crate::decompiler::recover_fields(self) {
                return crate::decompiler::field_rows_of(self, &rec);
            }
        }
        self.field_rows_basic()
    }

    pub fn sref(&self, r: u64) -> Option<String> {
        resolve_string(self.profile, self.num_base, &self.vm, &self.iso, r)
    }

    /// 不克隆的字符串访问（pp/objs 热路径）
    #[inline]
    pub fn sref_str(&self, r: u64) -> Option<&str> {
        if r <= self.num_base {
            self.vm.strings.get(&r).and_then(|v| v.as_deref())
        } else {
            self.iso.strings.get(&r).and_then(|v| v.as_deref())
        }
    }

    pub fn class_of(&self, r: u64) -> Option<ClassRec> {
        let oc = if r <= self.num_base {
            self.vm.classes.get(&r).copied()
        } else {
            self.iso.classes.get(&r).copied()
        };
        if oc.is_some() {
            return oc;
        }
        let wc = if r <= self.num_base {
            self.vm.patch_classes.get(&r).copied()
        } else {
            self.iso.patch_classes.get(&r).copied()
        }?;
        if wc <= self.num_base {
            self.vm.classes.get(&wc).copied()
        } else {
            self.iso.classes.get(&wc).copied()
        }
    }

    pub fn lib_of(&self, r: u64) -> Option<(u64, u64)> {
        if r <= self.num_base {
            self.vm.libraries.get(&r).map(|l| (l.name_ref, l.url_ref))
        } else {
            self.iso.libraries.get(&r).map(|l| (l.name_ref, l.url_ref))
        }
    }

    pub fn type_cid(&self, r: u64) -> Option<u64> {
        if r <= self.num_base {
            self.vm.type_cids.get(&r).copied()
        } else {
            self.iso.type_cids.get(&r).copied()
        }
    }

    /// 函数 code_index → entry（file-offset 空间）。
    ///
    /// 返回 None = 这个 Code 对象不指向可反汇编的真实函数体：`ci <= code_base_ref` 的是
    /// **stub 段**的 Code（分配 stub / 类型测试 stub / dispatch 桩，实测 167 个），
    /// `idx < first_entry` 的是分发表桩。它们的**入口地址在指令表里是有的**，只是没有
    /// 独立的函数体——所以 `export/stubs.rs` 会把这些「无人认领的表项」如实列出来，
    /// 能解出类名的（分配 stub）就写上名字。
    pub fn entry_for(&self, ci: u64) -> Option<(u64, usize)> {
        if ci <= self.code_base_ref {
            return None;
        }
        let idx = (ci - self.code_base_ref - 1) as usize;
        if (idx as u64) < self.first_entry {
            return None;
        }
        if idx >= self.pc_offsets.len() {
            return None;
        }
        let eo = self.entry_offset(idx);
        let ep = self.instr_base + self.pc_offsets[idx] + eo;
        if ep < self.platform.code_floor {
            return None; // 容器头区域的假条目（去符号回退场景），见 PlatformProfile.code_floor
        }
        Some((ep, idx))
    }

    fn build_name_by_ep(&mut self) {
        // 诊断：Code 对象为什么没能映射到指令表条目（覆盖率缺口归因）
        if std::env::var("DART_AOT_VERBOSE").is_ok() {
            let (mut c_le_base, mut c_idx_lt_first, mut c_oob, mut c_floor, mut c_ok) =
                (0usize, 0usize, 0usize, 0usize, 0usize);
            for f in self.iso.functions.values() {
                let ci = f.code_index;
                if ci <= self.code_base_ref {
                    c_le_base += 1;
                    continue;
                }
                let idx = (ci - self.code_base_ref - 1) as usize;
                if (idx as u64) < self.first_entry {
                    c_idx_lt_first += 1;
                    continue;
                }
                if idx >= self.pc_offsets.len() {
                    c_oob += 1;
                    continue;
                }
                let ep = self.instr_base + self.pc_offsets[idx] + self.entry_offset(idx);
                if ep < self.platform.code_floor {
                    c_floor += 1;
                    continue;
                }
                c_ok += 1;
            }
            eprintln!(
                "[dbg-map] code_obj: ok={c_ok} ci<=base={c_le_base} idx<first_entry={c_idx_lt_first} idx_oob={c_oob} below_floor={c_floor}; table={} first_entry={} base_ref={}",
                self.pc_offsets.len(),
                self.first_entry,
                self.code_base_ref
            );
        }
        for (&ref_, f) in self.iso.functions.iter() {
            if let Some(ep_idx) = self.entry_for(f.code_index) {
                self.func_eps.insert(ref_, ep_idx);
            }
        }

        // 分块并行：每块产出局部 BTreeMap（ep 首见），按块序 entry.or_insert 合并
        let funcs: Vec<(u64, (u64, usize))> = self
            .func_eps
            .iter()
            .map(|(r, e)| (*r, *e))
            .collect();
        let n_threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .min(8)
            .max(1);
        let n = funcs.len();
        let chunk = n.div_ceil(n_threads).max(1);
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        let mut b = 0usize;
        while b < n {
            let e = (b + chunk).min(n);
            ranges.push((b, e));
            b = e;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let funcs_ref = &funcs[..];
        let iso_ref = &self.iso;
        let vm_ref = &self.vm;
        let num_base = self.num_base;
        let functions_ref = &self.iso.functions;
        std::thread::scope(|scope| {
            for (pi, &(b, e)) in ranges.iter().enumerate() {
                let tx = tx.clone();
                scope.spawn(move || {
                    let mut local: BTreeMap<u64, String> = BTreeMap::new();
                    let funcs_slice = &funcs_ref[b..e];
                    let nr = num_base;
                    for &(ref_, (ep, _idx)) in funcs_slice {
                        let f = functions_ref.get(&ref_).unwrap();
                        let owner = if f.owner_ref <= nr {
                            vm_ref.classes.get(&f.owner_ref).copied().or_else(|| {
                                vm_ref
                                    .patch_classes
                                    .get(&f.owner_ref)
                                    .and_then(|w| vm_ref.classes.get(w))
                                    .copied()
                            })
                        } else {
                            iso_ref.classes.get(&f.owner_ref).copied().or_else(|| {
                                iso_ref
                                    .patch_classes
                                    .get(&f.owner_ref)
                                    .and_then(|w| iso_ref.classes.get(w))
                                    .copied()
                            })
                        };
                        let cls = owner
                            .map(|o| scrub_name(self_str(vm_ref, iso_ref, nr, o.name_ref)))
                            .unwrap_or_default();
                        let lib = owner
                            .and_then(|o| {
                                let l = if o.library_ref <= nr {
                                    vm_ref.libraries.get(&o.library_ref)
                                } else {
                                    iso_ref.libraries.get(&o.library_ref)
                                }?;
                                let url = self_str(vm_ref, iso_ref, nr, l.url_ref).unwrap_or("");
                                if url.is_empty() {
                                    None
                                } else {
                                    Some(library_name(url))
                                }
                            })
                            .unwrap_or_default();
                        let vk = f.kind_tag & 0x1F;
                        let st = (f.kind_tag >> 16) & 1 != 0;
                        let fn_ = scrub_name(self_str(vm_ref, iso_ref, nr, f.name_ref));
                        let mangled =
                            get_function_name_4_ida(&fn_, &cls, func_blutter_kind(vk), vk, st);
                        local.entry(ep).or_insert_with(|| format!("{lib}_{cls}::{mangled}"));
                    }
                    let _ = tx.send((pi, local));
                });
            }
            drop(tx);
        });
        let mut parts: Vec<Option<BTreeMap<u64, String>>> =
            (0..ranges.len()).map(|_| None).collect();
        for (pi, m) in rx {
            parts[pi] = Some(m);
        }
        for part in parts.into_iter().flatten() {
            for (ep, name) in part {
                self.name_by_ep.entry(ep).or_insert(name);
            }
        }
    }

    /// library → class → function 分组。
    /// include_dart_libs=false 时跳过 dart: SDK 内部库（blutter 默认口径，用于 asm 等
    /// 聚焦应用代码的产物）；true 时全量纳入（用于 r2/IDA 命名，避免 SDK 内部函数
    /// 在反编译工具里只剩混淆名/默认名）。
    /// 保持 Python dict 插入序语义：lib 与 cls 按函数 ref 升序的首现顺序，
    /// 类内函数按 ref 升序。
    pub fn build_functions(&self, include_dart_libs: bool) -> LibGroups {
        struct Lib {
            classes: Vec<(String, Vec<FuncEntry>)>,
            index: std::collections::HashMap<String, usize>,
        }
        let mut libs: Vec<(String, Lib)> = Vec::new();
        let mut lib_lookup: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        for (&ref_, f) in self.iso.functions.iter() {
            let Some((ep, idx)) = self.func_eps.get(&ref_).copied() else { continue };
            let owner = self.class_of(f.owner_ref);
            let cls = owner
                .map(|o| scrub_name(self.sref_str(o.name_ref)))
                .unwrap_or_default();
            let raw_url: &str = owner
                .and_then(|o| self.lib_of(o.library_ref))
                .and_then(|(_, url_ref)| self.sref_str(url_ref))
                .unwrap_or("");
            if !include_dart_libs && raw_url.starts_with("dart:") {
                continue; // 默认跳过 SDK 内部库（供 asm 等聚焦产物使用）
            }
            let lib = if raw_url.is_empty() {
                String::new()
            } else {
                library_name(raw_url)
            };
            let vk = f.kind_tag & 0x1F;
            let st = (f.kind_tag >> 16) & 1 != 0;
            let bkind = func_blutter_kind(vk);
            let mut fn_ = scrub_name(self.sref_str(f.name_ref));
            // 过渡版（2.16/2.18 等）函数名不在 fill：入口正确但 name_ref 为空时按地址回填 ELF 符号
            if self.profile.format.elf_name_backfill && fn_.is_empty() {
                if let Some(sym) = self.elf_names.get(&ep) {
                    fn_ = clean_elf_fn(sym);
                }
            }
            let mangled = get_function_name_4_ida(&fn_, &cls, bkind, vk, st);

            let li = match lib_lookup.get(&lib) {
                Some(&i) => i,
                None => {
                    let i = libs.len();
                    lib_lookup.insert(lib.clone(), i);
                    libs.push((
                        lib.clone(),
                        Lib { classes: Vec::new(), index: std::collections::HashMap::new() },
                    ));
                    i
                }
            };
            let l = &mut libs[li].1;
            let ci = match l.index.get(&cls) {
                Some(&i) => i,
                None => {
                    let i = l.classes.len();
                    l.index.insert(cls.clone(), i);
                    l.classes.push((cls.clone(), Vec::new()));
                    i
                }
            };
            l.classes[ci].1.push(FuncEntry { ep, lib, cls, mangled, idx });
        }
        libs.into_iter()
            .map(|(lib, l)| (lib, l.classes))
            .collect()
    }

    /// 函数精确大小 = pc_offsets[idx+1] - pc_offsets[idx]；末条退化为 0x200
    /// （对应参考实现 _code_size）。注意这是**从 payload 边界**量的长度；
    /// 多态入口（entry_for 的 eo）要从头部扣掉，故地址相关消费方应改用 code_range。
    pub fn code_size(&self, idx: usize) -> u64 {
        let n = self.pc_offsets.len();
        if (idx as u64) < self.first_entry || idx >= n {
            return 0;
        }
        if idx + 1 < n {
            return self.pc_offsets[idx + 1].saturating_sub(self.pc_offsets[idx]);
        }
        0x200
    }

    /// 多态入口偏移 eo（payload 内、真实入口之前的那几个字节的桩）。非多态为 0。
    pub fn entry_offset(&self, idx: usize) -> u64 {
        if idx < self.first_entry as usize {
            return 0;
        }
        let cluster_index = idx - self.first_entry as usize;
        if self
            .payload_infos
            .get(cluster_index)
            .map(|p| p & 1 != 0)
            .unwrap_or(false)
        {
            self.platform.polymorphic_entry_offset_aot as u64
        } else {
            0
        }
    }

    /// 函数 (入口地址, 可反汇编字节数)。
    ///
    /// 入口 = payload + eo：arm64 的多态入口会在 payload 前面放一段桩，**真实代码在
    /// payload+24**；从 payload 起反汇编会把桩当成函数体，且长度也会多算 eo 字节。
    pub fn code_range(&self, idx: usize) -> Option<(u64, u64)> {
        let size = self.code_size(idx);
        if idx >= self.pc_offsets.len() {
            return None;
        }
        let eo = self.entry_offset(idx);
        if size <= eo {
            return None;
        }
        let size = size - eo;
        // 长度上界：函数不可能比文件还大。某些版本（2.10）的 text-offset 序列会给出
        // 荒谬的差值，不拦住的话下游 `foff + csize` 会**回绕**并绕过边界检查，
        // 直接崩在切片索引上（实测 2.10.4 rc=101）。
        if size > self.data.len() as u64 {
            return None;
        }
        let start = self.instr_base + self.pc_offsets[idx] + eo;
        if start.checked_add(size)? > self.data.len() as u64 + self.slice_off {
            return None;
        }
        Some((start, size))
    }

    /// ref → 所属 cluster 的 cid（含 VM base，参考 cid_of_obj）。二分索引 O(log n)。
    #[inline]
    pub fn cid_of_obj(&self, ref_: u64) -> Option<u64> {
        if ref_ > self.num_base {
            self.iso.cid_at(ref_)
        } else {
            self.vm.cid_at(ref_)
        }
    }

    pub fn instance_fields(&self) -> &BTreeMap<u64, (u64, Vec<FieldVal>)> {
        &self.iso.instance_fields
    }

    /// frida Classes 数组条目（参考实现 _class_entry）。
    /// 特殊类（bool/int/double/String/List/Map/Closure/Object…）用静态名 + 偏移，
    /// TypedData 整数类带 lenOffset/dataOffset，其余预定义类 {id,name}，
    /// 用户类带 fbitmap/sid/size/argOffset。
    pub fn class_entry_string(&self, cid: i64, entry: Option<(u64, ClassRec)>) -> Option<String> {
        // frida 布局阈值：现代系（2.15+）沿用历史基线硬编码（176/113..168，与各版本
        // 已对拍存档逐字节一致）；≤2.14 时代按 profile 实际值驱动
        let legacy = self.profile.format.string_clusters_separate;
        let predef = if legacy { self.profile.alloc.instance_min as i64 } else { 176 };
        let tlo = if legacy {
            self.profile.alloc.typed_data_first as i64
        } else {
            113
        };
        let thi = if legacy { tlo + self.profile.alloc.typed_data_count as i64 } else { 169 };
        if entry.is_none() {
            if cid < predef {
                return self
                    .profile
                    .class_id_names
                    .get(&cid.to_string())
                    .cloned()
                    .map(|name| format!("{{id:{cid},name:\"{name}\"}}"));
            }
            return None;
        }
        let c = entry.unwrap().1;
        let mut name = scrub_name(self.sref(c.name_ref).as_deref());
        if name.is_empty() && cid < predef {
            name = self
                .profile
                .class_id_names
                .get(&cid.to_string())
                .cloned()
                .unwrap_or_default();
        }
        // 预设特殊类（62/60/61/93/94/89/91/85/87/56/44）
        if cid < predef {
            if let Some(spec) = self.profile.frida_special_layouts.get(&cid.to_string()) {
                let spec_name = spec.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let mut s = format!("{{id:{cid},name:\"{spec_name}\"");
                if let Some(fields) = spec.get("fields").and_then(|v| v.as_object()) {
                    for (k, v) in fields {
                        if let Some(n) = v.as_i64() {
                            s.push_str(&format!(",{k}:{n}"));
                        }
                    }
                }
                s.push('}');
                return Some(s);
            }
        }
        // TypedData 范围（本版本 typed_data_first..+count）
        if (tlo..thi).contains(&cid) {
            if name.is_empty() {
                return None;
            }
            if self.profile.frida_int_typed_cids.contains(&(cid as u64)) {
                return Some(format!("{{id:{cid},name:\"{name}\",lenOffset:16,dataOffset:24}}"));
            }
            return Some(format!("{{id:{cid},name:\"{name}\"}}"));
        }
        if cid < predef {
            return Some(format!("{{id:{cid},name:\"{name}\"}}"));
        }
        // 用户类
        let sid = if c.super_type_ref <= self.num_base {
            self.vm.type_cids.get(&c.super_type_ref).copied().unwrap_or(0)
        } else {
            self.iso.type_cids.get(&c.super_type_ref).copied().unwrap_or(0)
        };
        let size = c.next_field_off * 8;
        let arg_off = if c.type_arg_off > 0 { c.type_arg_off * 8 } else { -1 };
        Some(format!(
            "{{id:{cid},name:\"{name}\",fbitmap:{},sid:{sid},size:{size},argOffset:{arg_off}}}",
            c.field_bitmap
        ))
    }
}

/// resolve_string：ref <= num_base → VM 快照字符串，否则 isolate。
fn resolve_string(
    _profile: &SdkProfile,
    num_base: u64,
    vm: &Snapshot,
    iso: &Snapshot,
    r: u64,
) -> Option<String> {
    if r <= num_base {
        vm.strings.get(&r).cloned().flatten()
    } else {
        iso.strings.get(&r).cloned().flatten()
    }
}

/// 借用版字符串解析（并行块内用）
#[inline]
fn self_str<'a>(vm: &'a Snapshot, iso: &'a Snapshot, num_base: u64, r: u64) -> Option<&'a str> {    if r <= num_base {
        vm.strings.get(&r).and_then(|v| v.as_deref())
    } else {
        iso.strings.get(&r).and_then(|v| v.as_deref())
    }
}

fn n_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(8)
        .max(1)
}

/// 清洗 ELF 函数符号名 → 简单可读名。去除 Precompiled_ 前缀、尾随 _<数字>；
/// "Class.method_N" 取方法部分；无方法则去数字后整体。
fn clean_elf_fn(sym: &str) -> String {
    let mut s = sym.to_string();
    if let Some(r) = s.strip_prefix("Precompiled_") {
        s = r.to_string();
    }
    // 去除尾随 _<digits>（dedup 计数器）
    if let Some(pos) = s.rfind('_') {
        let tail = &s[pos + 1..];
        if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) {
            s.truncate(pos);
        }
    }
    // Class.method → method；含 '.' 则取最后一段
    if let Some(dot) = s.rfind('.') {
        let m = &s[dot + 1..];
        if !m.is_empty() {
            return m.to_string();
        }
    }
    s
}

/// 从 ELF 二进制提取函数符号 {地址 → 符号名}（2.16/2.18 等函数名不在 fill ref 的
/// 过渡版 special-handling：入口正确但名字缺失时，按地址回填 ELF 函数符号名）。
/// 只解析 STT_FUNC / 全局或本地文本符号（type T/t），st_value 即地址空间。
fn elf_function_names(data: &[u8]) -> BTreeMap<u64, String> {
    let mut out = BTreeMap::new();
    if data.len() < 0x40 || &data[0..4] != b"\x7fELF" {
        return out;
    }
    // e_shoff(0x28 u64), e_shentsize(0x3a u16), e_shnum(0x3c u16), e_shstrndx(0x3e u16)
    // ELF (x86-64/etc) 为小端；以下一律按小端读。
    let le = |o: usize, n: usize| -> usize {
        if o.checked_add(n).map_or(true, |e| e > data.len()) {
            usize::MAX
        } else {
            let mut v = 0usize;
            for i in 0..n {
                v |= (data[o + i] as usize) << (8 * i);
            }
            v
        }
    };
    let u32le = |o: usize| -> u32 {
        if o + 4 <= data.len() {
            u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]])
        } else {
            0
        }
    };
    let u64le = |o: usize| -> u64 {
        if o + 8 <= data.len() {
            let mut v = 0u64;
            for i in 0..8 {
                v |= (data[o + i] as u64) << (8 * i);
            }
            v
        } else {
            0
        }
    };
    let e_shoff = le(0x28, 8);
    let e_shentsize = le(0x3a, 2);
    let e_shnum = le(0x3c, 2);
    if e_shoff == usize::MAX || e_shentsize == 0 {
        return out;
    }
    // 收集 strtab（sh_link → offset/size）
    let mut strtabs: BTreeMap<u32, (usize, usize)> = BTreeMap::new();
    for i in 0..e_shnum {
        let sh = e_shoff + i * e_shentsize;
        if sh + 0x28 > data.len() {
            break;
        }
        let sh_type = u32le(sh + 0x04);
        if sh_type == 3 {
            let sh_offset = le(sh + 0x18, 8);
            let sh_size = le(sh + 0x20, 8);
            strtabs.insert(i as u32, (sh_offset, sh_size));
        }
    }
    // 直接扫每个符号条目（st_value 0 跳过）
    for shi in 0..e_shnum {
        let sh = e_shoff + shi * e_shentsize;
        if sh + 0x40 > data.len() {
            break;
        }
        let sh_type = u32le(sh + 0x04);
        if sh_type != 2 && sh_type != 11 {
            continue;
        }
        let sh_offset = le(sh + 0x18, 8);
        let sh_size = le(sh + 0x20, 8);
        let sh_link = u32le(sh + 0x28) as u32;
        let sh_entsize = le(sh + 0x38, 8);
        let entsize = if sh_entsize == 0 { 24 } else { sh_entsize };
        let (stro, strsz) = match strtabs.get(&sh_link) {
            Some((o, s)) => (*o, *s),
            None => continue,
        };
        let mut idx = 0usize;
        while idx + entsize <= sh_size {
            let ent = sh_offset + idx;
            if ent + 24 > data.len() {
                break;
            }
            let st_name = u32le(ent);
            let st_info = data[ent + 4];
            let st_value = u64le(ent + 8);
            let st_type = st_info & 0xf;
            if st_type == 2 && st_value != 0 && (st_name as usize) < strsz {
                let ns = stro + st_name as usize;
                let end = data[ns..(ns + 64).min(data.len())]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(0);
                let nm = String::from_utf8_lossy(&data[ns..ns + end]).to_string();
                if !nm.is_empty() {
                    out.entry(st_value).or_insert(nm);
                }
            }
            idx += entsize;
        }
    }
    out
}

/// 分块并行计算 cname：（iso 类、vm 类）各分块 → 每块 BTreeMap，按序返回
fn chunked_merge2<'a>(
    iso_list: &'a [(u64, ClassRec)],
    vm_list: &'a [(u64, ClassRec)],
    num_base: u64,
    profile: &'a SdkProfile,
    vm: &'a Snapshot<'a>,
    iso: &'a Snapshot<'a>,
) -> Vec<BTreeMap<i64, String>> {
    let nt = n_threads();
    let total = iso_list.len() + vm_list.len();
    let chunk = total.div_ceil(nt).max(1);
    // 把 iso+vm 序列视作连续区间（iso 段在前），各块产出首见映射
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        let mut b = 0usize;
        let mut pi = 0usize;
        while b < total {
            let e = (b + chunk).min(total);
            let tx = tx.clone();
            scope.spawn(move || {
                let mut m = BTreeMap::new();
                for idx in b..e {
                    let (name_ref, cid) = if idx < iso_list.len() {
                        let c = &iso_list[idx].1;
                        (c.name_ref, c.class_id)
                    } else {
                        let c = &vm_list[idx - iso_list.len()].1;
                        (c.name_ref, c.class_id)
                    };
                    let name =
                        scrub_name(resolve_string(profile, num_base, vm, iso, name_ref).as_deref());
                    m.entry(cid).or_insert_with(|| name);
                }
                let _ = tx.send((pi, m));
            });
            b = e;
            pi += 1;
        }
        drop(tx);
    });
    let nparts = total.div_ceil(chunk);
    let mut out: Vec<Option<BTreeMap<i64, String>>> = (0..nparts).map(|_| None).collect();
    for (pi, m) in rx {
        out[pi] = Some(m);
    }
    out.into_iter().flatten().collect()
}

/// 分块计算 parent_of/nfo（同 cid 后见覆盖 → 按序 merge 即 insert）
fn chunked_parent<'a>(
    iso_list: &'a [(u64, ClassRec)],
    num_base: u64,
    vm: &'a Snapshot<'a>,
    iso: &'a Snapshot<'a>,
) -> Vec<(BTreeMap<i64, i64>, BTreeMap<i64, i64>)> {
    let nt = n_threads();
    let chunk = iso_list.len().div_ceil(nt).max(1);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        let mut b = 0usize;
        let mut pi = 0usize;
        while b < iso_list.len() {
            let e = (b + chunk).min(iso_list.len());
            let tx = tx.clone();
            scope.spawn(move || {
                let mut pm = BTreeMap::new();
                let mut nm = BTreeMap::new();
                for &(_, c) in &iso_list[b..e] {
                    let cid = c.class_id;
                    let p = if c.super_type_ref <= num_base {
                        vm.type_cids.get(&c.super_type_ref).copied()
                    } else {
                        iso.type_cids.get(&c.super_type_ref).copied()
                    }
                    .unwrap_or(0);
                    pm.insert(cid, p as i64);
                    nm.insert(cid, c.next_field_off);
                }
                let _ = tx.send((pi, (pm, nm)));
            });
            b = e;
            pi += 1;
        }
        drop(tx);
    });
    let nparts = iso_list.len().div_ceil(chunk);
    let mut out: Vec<Option<(BTreeMap<i64, i64>, BTreeMap<i64, i64>)>> =
        (0..nparts).map(|_| None).collect();
    for (pi, m) in rx {
        out[pi] = Some(m);
    }
    out.into_iter().flatten().collect()
}