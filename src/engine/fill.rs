//! fill 阶段 DSL 解释器：按 SDK Profile 的 cluster_layouts 逐字段读对象。
//!
//! 布局 = 步骤列表，逐对象（k = 0..count）执行；引擎固定的内置布局：
//! - string 类（cid==string_cid）：按 rodata offsets 解码字符串，无 fill 读
//! - rodata/mint 类：fill 空（mint 值在 alloc 捕获）
//! - instance 类：bitmap(每 cluster 一次) + nfo-1 个 slot 循环（word32x2 或 ref）
//! - typed data（rem 0/2）：length + raw 字节跳过；view（rem 1/3）：3 refs + 2 svarint
//!
//! 性能设计：每个 cluster 的 steps 先编译成 CStep（alias 名 → slot id 一次映射），
//! 逐对象执行时 ctx 为 Vec<Option<i64>>（无哈希、无字符串克隆）。

use crate::engine::snapshot::{
    ClassRec, ClusterMeta, FieldVal, FunctionRec, LibraryRec, PoolEntry, Snapshot,
};
use crate::engine::varint::Reader;
use crate::profile::{LoopTimes, SdkProfile, Step};
use std::collections::HashMap;

thread_local! {
    static FILL2_PREV: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub fn fill_snapshot<'a>(
    profile: &'a SdkProfile,
    snap: &mut Snapshot<'a>,
    out: Option<&mut Vec<String>>,
) -> Result<(), String> {
    let _ = out; // 预留：fill 层目前没有独立告警输出
    let clusters = std::mem::take(&mut snap.clusters);
    let mut r = Reader::new(snap.data);
    r.pos = snap.alloc_end;

    // Instance cluster 的 bitmap（cluster 级，跨对象保留）
    let mut instance_bitmaps: HashMap<u64, u64> = HashMap::new();

    for (m_idx, meta) in clusters.iter().enumerate() {
        let cid = meta.cid;
        let count = meta.count;
        let start_ref = meta.start_ref;

        // 字符串：fill 空，按 rodata offsets 解码。
        // 2.15+ 集中在 string_cid 一个簇（对象 tags 区分单/双字节）；
        // ≤2.14（string_clusters_separate）则 string/one_byte/two_byte 三个 cid
        // 各自成 ROData 簇，均需按 offsets 解码。
        if cid == profile.alloc.string_cid
            || (profile.format.string_clusters_separate
                && (cid == profile.alloc.one_byte_string_cid
                    || cid == profile.alloc.two_byte_string_cid))
        {
            for k in 0..count {
                let off = *meta.offsets.get(k as usize).ok_or(format!(
                    "string cluster {m_idx} 缺少 offset[{k}]"
                ))?;
                snap.strings.insert(start_ref + k, snap.decode_string_at(profile, off));
            }
            if std::env::var("DART_AOT_DEBUG_STRINGS").is_ok() {
                for (k, r) in (start_ref..start_ref + count).enumerate() {
                    if r < 4000 {
                        let off = meta.offsets.get(k).copied().unwrap_or(0);
                        let di = snap.data_image;
                        let bs = if di + off as usize + 16 <= snap.data.len() {
                            format!("{:02x?}", &snap.data[di + off as usize..di + off as usize + 16])
                        } else {
                            "OOB".to_string()
                        };
                        eprintln!("[dbg-str] ref={r} off={off:#x} data_image={di:#x} bytes={bs} decoded={:?}",
                            snap.strings.get(&r));
                    }
                }
            }
            continue;
        }
        if meta.kind == "rodata" || cid == profile.alloc.mint_cid {
            continue;
        }

        let steps: &[Step] = match resolve_layout(profile, cid) {
            Some(s) => s,
            None => {
                return Err(format!(
                    "cluster {m_idx}: 无 cid {cid} 的 fill 布局（kind={}）。请在 SDK Profile cluster_layouts 中添加",
                    meta.kind
                ));
            }
        };

        // Class 双段：predefined 段与常规段布局不同（老版仅在 pre 有 bitmap/条件）
        let (steps_pre, steps_post): (&[Step], &[Step]) = {
            if let Some(ss) = profile.cluster_layouts.get(&cid.to_string()) {
                (ss.pre(), ss.post())
            } else {
                (steps, steps)
            }
        };

        // 编译：alias 名 → slot id（每 cluster 一次）
        let mut slot_names: HashMap<&'a str, u32> = HashMap::new();
        let mut list_names: HashMap<&'a str, u32> = HashMap::new();
        // legacy Code 簇（不使用内建 `Code` 步骤）也需 code_start_ref 供地址层 code_base_ref。
        // 与 CStep::Code 一致：每次覆盖，使最后一个（ISO）代码簇生效（函数在 ISO side）。
        if meta.kind == "code" {
            snap.code_start_ref = Some(meta.start_ref);
        }
        if std::env::var("DART_AOT_DEBUG_FILL").is_ok() {
            eprintln!("[dbg-fill] cluster #{m_idx} cid={cid} count={count} kind={} predef={} def={} pos={:#x}",
                meta.kind, meta.predefined_count, meta.deferred, r.pos);
        }
        if std::env::var("DART_AOT_DEBUG_FILL2").is_ok() {
            // 消费字节 = 本簇起点与上一簇起点的差（用模块级单例记）
            let prev = FILL2_PREV.with(|c| c.replace(r.pos));
            eprintln!("[dbg-fill2] cluster #{m_idx} cid={cid} count={count} kind={} consumed={}",
                meta.kind, r.pos.saturating_sub(prev));
        }
        let codec = match profile.format.ref_encoding.as_str() {
            "ref_id_128" => RefCodec::RefId128,
            "unsigned_leb128" => RefCodec::UnsignedLeb,
            "signed_varint" => RefCodec::SignedVarint,
            other => return Err(format!("未知 ref_encoding {other:?}（profile.format.ref_encoding）")),
        };
        let compiled = compile_steps(steps_pre, &mut slot_names, &mut list_names)?;
        let compiled_post: Option<Vec<CStep>> = if std::ptr::eq(steps_pre, steps_post) {
            None
        } else {
            Some(compile_steps(steps_post, &mut slot_names, &mut list_names)?)
        };
        let n_slots = slot_names.len();
        let n_lists = list_names.len();

        let mut ctx: Vec<Option<i64>> = vec![None; n_slots];
        let mut lists: Vec<Vec<i64>> = vec![Vec::new(); n_lists];
        // 2.18.x 专属：Code/Class 簇 fill 起点修正（前置 ISO Code 簇多读 4 字节、Class 前多读 2 字节，
        // 连锁致函数名/类名偏移）。profile 驱动。
        let adj = if meta.kind == "class" {
            profile.format.class_fill_adj
        } else if meta.kind == "code" {
            profile.format.code_fill_adj
        } else {
            0
        };        if adj != 0 {
            if adj >= 0 {
                r.skip(adj as usize).map_err(|e| format!("fill_adj: {e:?}"))?;
            } else if r.pos >= (-adj) as usize {
                r.pos -= (-adj) as usize;
            }
        }
        if let (Some(c), Some(d)) = (
            std::env::var("DART_AOT_FILL_DELTA_CID").ok().and_then(|s| s.parse::<u64>().ok()),
            std::env::var("DART_AOT_FILL_DELTA_VAL").ok().and_then(|s| s.parse::<i64>().ok()),
        ) {
            if meta.cid == c {
                if d >= 0 {
                    r.skip(d as usize).map_err(|e| format!("cid_delta: {e:?}"))?;
                } else if r.pos >= (-d) as usize {
                    r.pos -= (-d) as usize;
                }
            }
        }
        for k in 0..count {
            for v in ctx.iter_mut() {
                *v = None;
            }
            for l in lists.iter_mut() {
                l.clear();
            }
            let sel: &[CStep] = if let Some(cp) = compiled_post.as_deref() {
                if k >= meta.predefined_count {
                    cp
                } else {
                    &compiled
                }
            } else {
                &compiled
            };
            exec_compiled(
                profile,
                snap,
                &mut r,
                meta,
                k,
                sel,
                &mut ctx,
                &mut lists,
                &mut instance_bitmaps,
                codec,
            )
            .map_err(|e| format!("cluster cid {} kind {} 对象#{k}: {e}", meta.cid, meta.kind))?;
            if std::env::var("DART_AOT_OBJ_STEPS").is_ok() && k < 5 {
                eprintln!("[dbg-obj] cid={} k={} pos={}", meta.cid, k, r.pos);
            }
        }
    }

    if std::env::var("DART_AOT_DEBUG_FILLPOS").is_ok() {
        eprintln!(
            "[dbg-fillpos] snap alloc_end={:#x} fill_end={:#x} len={}",
            snap.alloc_end,
            r.pos,
            snap.length
        );
    }
    snap.clusters = clusters;
    Ok(())
}

/// 布局解析：显式 cluster_layouts[cid] → 内置（instance/typed/typed_view）
fn resolve_layout<'a>(profile: &'a SdkProfile, cid: u64) -> Option<&'a [Step]> {
    if let Some(ss) = profile.cluster_layouts.get(&cid.to_string()) {
        return Some(ss.pre());
    }
    if profile.alloc_kind(cid) == "instance" {
        return Some(BUILTIN_INSTANCE);
    }
    if profile.typed_data_slot(cid).is_some() {
        if profile.format.instance_legacy {
            // ≤2.9：internal=[U,B,skip]、view=[B,3refs]、external=[U,align8,skip]
            return Some(match profile.typed_data_rem(cid) {
                Some(0) => BUILTIN_TYPED27_INTERNAL,
                Some(1) => BUILTIN_TYPED27_VIEW,
                _ => BUILTIN_TYPED27_EXTERNAL,
            });
        }
        if profile.is_view_kind(cid) {
            return Some(BUILTIN_TYPED_VIEW);
        }
        return Some(BUILTIN_TYPED_DATA);
    }
    None
}

static BUILTIN_INSTANCE: &[Step] = &[Step::InstanceFields];
static BUILTIN_TYPED_VIEW: &[Step] = &[Step::Refs {
    n: 3,
    aliases: Vec::new(),
    collect: None,
}, Step::Svarint {
    alias: None,
    collect: None,
}, Step::Svarint {
    alias: None,
    collect: None,
}];
static BUILTIN_TYPED_DATA: &[Step] = &[Step::Uvarint {
    alias: None,
    collect: None,
    transform: None,
}, Step::SkipRawElemWidth];
// ≤2.9 时代 typed 三态（instance_legacy=true 时生效）：
// internal=[U length, B is_canonical, skip payload]；view=[B is_canonical, 3 refs]；
// external=[U length, align8, skip payload]
static BUILTIN_TYPED27_INTERNAL: &[Step] = &[Step::Uvarint {
    alias: None,
    collect: None,
    transform: None,
}, Step::Byte {
    alias: None,
    collect: None,
}, Step::SkipRawElemWidth];
static BUILTIN_TYPED27_VIEW: &[Step] = &[Step::Byte {
    alias: None,
    collect: None,
}, Step::Refs {
    n: 3,
    aliases: Vec::new(),
    collect: None,
}];
static BUILTIN_TYPED27_EXTERNAL: &[Step] = &[Step::Uvarint {
    alias: None,
    collect: None,
    transform: None,
}, Step::SkipAlign { n: 8 }, Step::SkipRawElemWidth];

// ---------------------------------------------------------------- 编译形态

enum CStep {
    Refs {
        n: usize,
        aliases: Vec<(usize, u32)>,
        collect: Option<u32>,
    },
    Uv {
        slot: Option<u32>,
        collect: Option<u32>,
        transform: bool,
    },
    Sv {
        slot: Option<u32>,
        collect: Option<u32>,
    },
    Byte {
        slot: Option<u32>,
        collect: Option<u32>,
    },
    U32 {
        slot: Option<u32>,
        collect: Option<u32>,
    },
    TextOffset { signed: bool },
    Loop {
        times: LoopTimes,
        steps: Vec<CStep>,
    },
    Cond {
        on: u32,
        lt: Option<u64>,
        ge: Option<u64>,
        bit: Option<u32>,
        then: Vec<CStep>,
        otherwise: Vec<CStep>,
        default: Vec<(u32, i64)>,
    },
    SkipRawElemWidth,
    SkipConst(u64),
    SkipAlign(u64),
    ObjectPool,
    InstanceFields,
    Code,
    Emit(CStore),
}

enum CField {
    Slot(u32),
    Missing, // 编译期无法解析的字段：运行时照旧报错（正常 profile 不触发）
}

enum CStore {
    Functions {
        name_ref: CField,
        owner_ref: CField,
        sig_ref: CField,
        code_index: CField,
        kind_tag: CField,
    },
    Classes {
        name_ref: CField,
        library_ref: CField,
        class_id: CField,
        super_type_ref: CField,
        next_field_off: CField,
        type_arg_off: CField,
        field_bitmap: CField,
    },
    Libraries {
        name_ref: CField,
        url_ref: CField,
    },
    PatchClass { wrapped: CField },
    TypeCid { type_cid: CField },
    MapData { data_ref: CField, used_ref: CField },
    ArrayElements { ta: CField, elems: u32 },
}

fn compile_steps<'a>(
    steps: &'a [Step],
    slot_names: &mut HashMap<&'a str, u32>,
    list_names: &mut HashMap<&'a str, u32>,
) -> Result<Vec<CStep>, String> {
    let mut next = slot_names.len() as u32;
    let mut next_list = list_names.len() as u32;
    fn slot_of<'x>(name: &'x str, table: &mut HashMap<&'x str, u32>, next: &mut u32) -> u32 {
        if let Some(&s) = table.get(name) {
            return s;
        }
        let s = *next;
        *next += 1;
        table.insert(name, s);
        s
    }
    fn list_of<'x>(name: &'x str, table: &mut HashMap<&'x str, u32>, next: &mut u32) -> u32 {
        if let Some(&s) = table.get(name) {
            return s;
        }
        let s = *next;
        *next += 1;
        table.insert(name, s);
        s
    }

    let mut out = Vec::with_capacity(steps.len());
    for st in steps {
        out.push(match st {
            Step::Refs { n, aliases, collect } => {
                let mut cs_aliases = Vec::new();
                for (i, a) in aliases.iter().enumerate() {
                    if let Some(name) = a {
                        cs_aliases.push((i, slot_of(name.as_str(), slot_names, &mut next)));
                    }
                }
                CStep::Refs {
                    n: *n,
                    aliases: cs_aliases,
                    collect: collect.as_ref().map(|c| list_of(c.as_str(), list_names, &mut next_list)),
                }
            }
            Step::Uvarint { alias, collect, transform } => CStep::Uv {
                slot: alias.as_ref().map(|a| slot_of(a.as_str(), slot_names, &mut next)),
                collect: collect.as_ref().map(|c| list_of(c.as_str(), list_names, &mut next_list)),
                transform: transform.as_deref() == Some("shr4_and_mask"),
            },
            Step::Svarint { alias, collect } => CStep::Sv {
                slot: alias.as_ref().map(|a| slot_of(a.as_str(), slot_names, &mut next)),
                collect: collect.as_ref().map(|c| list_of(c.as_str(), list_names, &mut next_list)),
            },
            Step::Byte { alias, collect } => CStep::Byte {
                slot: alias.as_ref().map(|a| slot_of(a.as_str(), slot_names, &mut next)),
                collect: collect.as_ref().map(|c| list_of(c.as_str(), list_names, &mut next_list)),
            },
            Step::U32 { alias, collect } => CStep::U32 {
                slot: alias.as_ref().map(|a| slot_of(a.as_str(), slot_names, &mut next)),
                collect: collect.as_ref().map(|c| list_of(c.as_str(), list_names, &mut next_list)),
            },
            Step::TextOffset { signed } => CStep::TextOffset { signed: *signed },
            Step::Loop { times, steps } => CStep::Loop {
                times: times.clone(),
                steps: compile_steps(steps, slot_names, list_names)?,
            },
            Step::Cond { on, lt, ge, bit, then, else_steps, set_default } => CStep::Cond {
                on: slot_of(on.as_str(), slot_names, &mut next),
                lt: *lt,
                ge: *ge,
                bit: *bit,
                then: compile_steps(then, slot_names, list_names)?,
                otherwise: compile_steps(else_steps, slot_names, list_names)?,
                default: set_default
                    .iter()
                    .map(|(k, v)| (slot_of(k.as_str(), slot_names, &mut next), *v))
                    .collect(),
            },
            Step::SkipRawElemWidth => CStep::SkipRawElemWidth,
            Step::SkipConst { n } => CStep::SkipConst(*n),
            Step::SkipAlign { n } => CStep::SkipAlign(*n),
            Step::ObjectPool => CStep::ObjectPool,
            Step::InstanceFields => CStep::InstanceFields,
            Step::Code => CStep::Code,
            Step::Emit { store, fields } => {
                let mut f = |key: &str| match fields.get(key) {
                    Some(crate::profile::FieldSource::Alias(a)) => {
                        CField::Slot(slot_of(a.as_str(), slot_names, &mut next))
                    }
                    _ => CField::Missing,
                };
                CStep::Emit(match store.as_str() {
                    "functions" => CStore::Functions {
                        name_ref: f("name_ref"),
                        owner_ref: f("owner_ref"),
                        sig_ref: f("sig_ref"),
                        code_index: f("code_index"),
                        kind_tag: f("kind_tag"),
                    },
                    "classes" => CStore::Classes {
                        name_ref: f("name_ref"),
                        library_ref: f("library_ref"),
                        class_id: f("class_id"),
                        super_type_ref: f("super_type_ref"),
                        next_field_off: f("next_field_off"),
                        type_arg_off: f("type_arg_off"),
                        field_bitmap: f("field_bitmap"),
                    },
                    "libraries" => CStore::Libraries {
                        name_ref: f("name_ref"),
                        url_ref: f("url_ref"),
                    },
                    "patch_classes" => CStore::PatchClass { wrapped: f("wrapped_class") },
                    "type_cids" => CStore::TypeCid { type_cid: f("type_cid") },
                    "map_data" => CStore::MapData {
                        data_ref: f("data_ref"),
                        used_ref: f("used_ref"),
                    },
                    "array_elements" => CStore::ArrayElements {
                        ta: f("ta"),
                        elems: list_of("elems", list_names, &mut next_list),
                    },
                    other => return Err(format!("未知 emit store {other:?}")),
                })
            }
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------- 执行

fn gv(ctx: &[Option<i64>], field: &CField) -> Option<i64> {
    match field {
        CField::Slot(s) => ctx.get(*s as usize).copied().flatten(),
        CField::Missing => None,
    }
}

fn read_unsigned(r: &mut Reader) -> Result<u64, String> {
    r.read_unsigned().map_err(|e| format!("uvarint: {e:?}"))
}
fn read_signed(r: &mut Reader) -> Result<i64, String> {
    r.read_signed()
        .map_err(|e| format!("svarint @ {:#x}: {e:?}", r.pos))
}
#[derive(Clone, Copy)]
enum RefCodec {
    RefId128,
    UnsignedLeb,
    SignedVarint,
}

fn read_ref_codec(codec: RefCodec, r: &mut Reader) -> Result<u64, String> {
    match codec {
        RefCodec::RefId128 => r.read_ref().map_err(|e| format!("ref-id: {e:?}")),
        RefCodec::UnsignedLeb => r.read_unsigned().map_err(|e| format!("ref(leb): {e:?}")),
        RefCodec::SignedVarint => r.read_signed().map(|e| e as u64).map_err(|e| format!("ref(svarint): {e:?}")),
    }
}

fn length_of(meta: &ClusterMeta, k: u64) -> Result<u64, String> {
    meta.lengths
        .get(k as usize)
        .copied()
        .ok_or_else(|| format!("cluster cid {} 缺少 lengths[{k}]", meta.cid))
}

#[allow(clippy::too_many_arguments)]
fn exec_compiled<'a>(
    profile: &'a SdkProfile,
    snap: &mut Snapshot<'a>,
    r: &mut Reader<'a>,
    meta: &ClusterMeta,
    k: u64,
    steps: &[CStep],
    ctx: &mut [Option<i64>],
    lists: &mut [Vec<i64>],
    instance_bitmaps: &mut HashMap<u64, u64>,
    codec: RefCodec,
) -> Result<(), String> {
    for step in steps {
        match step {
            CStep::Refs { n, aliases, collect } => {
                for i in 0..*n {
                    let v = read_ref_codec(codec, r)?;
                    if let Some(&(_, slot)) = aliases.iter().find(|(ai, _)| *ai == i) {
                        ctx[slot as usize] = Some(v as i64);
                    }
                    if let Some(c) = collect {
                        lists[*c as usize].push(v as i64);
                    }
                }
            }
            CStep::Uv { slot, collect, transform } => {
                let mut v = read_unsigned(r)? as i64;
                if *transform {
                    v = (v >> 4) & profile.tagging.cid_tag_mask as i64;
                }
                if let Some(s) = slot {
                    ctx[*s as usize] = Some(v);
                }
                if let Some(c) = collect {
                    lists[*c as usize].push(v);
                }
            }
            CStep::Sv { slot, collect } => {
                let v = read_signed(r)?;
                if let Some(s) = slot {
                    ctx[*s as usize] = Some(v);
                }
                if let Some(c) = collect {
                    lists[*c as usize].push(v);
                }
            }
            CStep::Byte { slot, collect } => {
                let v = r.read_u8().map_err(|e| format!("byte: {e:?}"))? as i64;
                if let Some(s) = slot {
                    ctx[*s as usize] = Some(v);
                }
                if let Some(c) = collect {
                    lists[*c as usize].push(v);
                }
            }
            CStep::U32 { slot, collect } => {
                let v = r.read_u32_le().map_err(|e| format!("u32: {e:?}"))? as i64;
                if let Some(s) = slot {
                    ctx[*s as usize] = Some(v);
                }
                if let Some(c) = collect {
                    lists[*c as usize].push(v);
                }
            }
            CStep::TextOffset { signed } => {
                // 裸指令 legacy Code 簇：code 对象前导 text-offset delta，累加成 pc 偏移序列。
                // 与 CStep::Code 的 previous_text_offset_ 语义一致（整快照级累加）。
                // signed=true 用有符号变长读（2.10 特例）。
                let delta: i128 = if *signed {
                    read_signed(r)? as i128
                } else {
                    read_unsigned(r)? as i128
                };
                let tos = snap.text_offsets.get_or_insert_with(Vec::new);
                let prev = tos.last().copied().unwrap_or(0);
                tos.push((prev as i128 + delta) as u64);
            }
            CStep::Loop { times, steps } => {
                let n = match times {
                    LoopTimes::Named(name) if name == "lengths" => length_of(meta, k)?,
                    LoopTimes::Const(n) => *n,
                    LoopTimes::Named(other) => return Err(format!("未知 loop times \"{other}\"")),
                };
                for _ in 0..n {
                    exec_compiled(profile, snap, r, meta, k, steps, ctx, lists, instance_bitmaps, codec)?;
                }
            }
            CStep::Cond { on, lt, ge, bit, then, otherwise, default } => {
                let v = ctx
                    .get(*on as usize)
                    .copied()
                    .flatten()
                    .ok_or_else(|| format!("cluster cid {}: cond 引用了未捕获字段", meta.cid))?;
                let hit = lt.map(|t| (v as u64) < t).unwrap_or(false)
                    || ge.map(|t| (v as u64) >= t).unwrap_or(false)
                    || bit.map(|b| ((v as u64) >> b) & 1 == 1).unwrap_or(false);
                if hit {
                    exec_compiled(profile, snap, r, meta, k, then, ctx, lists, instance_bitmaps, codec)?;
                } else if !otherwise.is_empty() {
                    exec_compiled(profile, snap, r, meta, k, otherwise, ctx, lists, instance_bitmaps, codec)?;
                } else {
                    for (s, val) in default {
                        ctx[*s as usize] = Some(*val);
                    }
                }
            }
            CStep::SkipRawElemWidth => {
                let n = length_of(meta, k)? * profile.elem_width(meta.cid);
                r.skip(n as usize).map_err(|e| format!("skip_raw: {e:?}"))?;
            }
            CStep::SkipConst(n) => {
                r.skip(*n as usize).map_err(|e| format!("skip_const: {e:?}"))?;
            }
            CStep::SkipAlign(n) => {
                let pad = (n - (r.pos as u64 % n)) % n;
                r.skip(pad as usize).map_err(|e| format!("skip_align: {e:?}"))?;
            }
            CStep::ObjectPool => {
                // ≤2.16 裸指令 + 保留用户代码的样本：引擎对 2.10-2.14 部分簇的 fill
                // 布局比官方多读（2.12 实测：Function 布局 8 refs 实为 6、Field 6 refs
                // 实为 4，累计把 ObjectPool 起点推后 ~5000-6900 字节，长度读成垃圾；
                // 全平台复现、随源码排版变化，并非单一编译产物损坏）。
                //
                // 策略：正常快照按原语义直读；仅当直读长度明显越界（>100000）才启用
                // 重同步——在后续 ≤64 字节内找第一个「长度合理且全部条目可解码」的位置。
                // 垃圾区是 varint 流，任意偏移都可能碰巧解出若干"合法"条目，故不做候选
                // 打分（实测最大长度/端点对齐均会误选，甚至破坏干净样本）。
                // 已知局限：arm64 上漂移恰落小值(7)不触发重同步，对象池欠解析（不崩溃、
                // 对象层不受影响）；彻底修复需逐簇校正 2.10-2.14 fill 布局（见
                // artifacts/README「2.12 argv 变体跨平台验证」节）。
                let mut ln = read_unsigned(r)?;
                if std::env::var("DART_AOT_DEBUG_FILL").is_ok() {
                    eprintln!("[dbg-pool] ln={ln} pos={:#x}", r.pos);
                }
                if ln > 100000 {
                    let mut np = None;
                    for delta in 0..=64usize {
                        let p = r.pos + delta;
                        if p >= r.data.len() {
                            break;
                        }
                        let mut pr = Reader { data: r.data, pos: p };
                        if let Ok(v) = pr.read_unsigned() {
                            if v > 0 && v <= 100000 {
                                // 校验全部条目可解码，防选中 varint 流中的伪长度
                                let mut q = Reader { data: r.data, pos: pr.pos };
                                let mut ok = true;
                                for _ in 0..v {
                                    let bits = match q.read_u8() {
                                        Ok(b) => b,
                                        Err(_) => {
                                            ok = false;
                                            break;
                                        }
                                    };
                                    let behavior = (bits >> 5) & 0x7;
                                    if (2..=4).contains(&behavior) {
                                        continue;
                                    }
                                    let ok_entry = match bits & 0xF {
                                        1 => read_ref_codec(codec, &mut q).is_ok(),
                                        0 => q.read_signed().is_ok(),
                                        _ => true,
                                    };
                                    if !ok_entry {
                                        ok = false;
                                        break;
                                    }
                                }
                                if ok {
                                    np = Some(pr.pos);
                                    ln = v;
                                    break;
                                }
                            }
                        }
                    }
                    if let Some(p) = np {
                        if std::env::var("DART_AOT_DEBUG_FILL").is_ok() {
                            eprintln!("[dbg-pool] resync: 垃圾长度 → 真实 len={ln} pos={p:#x}");
                        }
                        r.pos = p;
                    }
                }
                let entries = snap.objectpool_entries.get_or_insert_with(Vec::new);
                let legacy = profile.format.objectpool_legacy;
                // 2.10–3.1：entry 位域 = TypeBits 位0-6（0=TaggedObject/1=Immediate/
                // 2+=Native）+ 位7 Patchable；3.3+ 才改为 SnapshotBehavior 位5-7。
                let pre33 = profile.format.objectpool_type_low7;
                // 3.2.x：EntryType 顺序交换（0=Immediate/1=TaggedObject），位域不变
                // （object.h: TypeBits = ObjectPoolBuilderEntry::TypeBits，逐版实证）。
                let swapped32 = profile.format.objectpool_type_low7_swapped;
                for _ in 0..ln {
                    let bits = r.read_u8().map_err(|e| format!("objectpool bits: {e:?}"))?;
                    if swapped32 {
                        match bits & 0x7F {
                            0 => {
                                let v = read_signed(r)?;
                                entries.push(PoolEntry { bits: bits as u64, typ: "imm".into(), value: Some(v) });
                            }
                            1 => {
                                let v = read_ref_codec(codec, r)?;
                                entries.push(PoolEntry { bits: bits as u64, typ: "obj".into(), value: Some(v as i64) });
                            }
                            _ => {
                                entries.push(PoolEntry { bits: bits as u64, typ: "native".into(), value: None });
                            }
                        }
                        continue;
                    }
                    if pre33 {
                        // 2.10–3.1：TypeBits=位0-6；0=TaggedObject(ref)/1=Immediate(svarint)/
                        // 其余=Native（无值）。位7 是 Patchable，不影响读取。
                        match bits & 0x7F {
                            0 => {
                                let v = read_ref_codec(codec, r)?;
                                entries.push(PoolEntry { bits: bits as u64, typ: "obj".into(), value: Some(v as i64) });
                            }
                            1 => {
                                let v = read_signed(r)?;
                                entries.push(PoolEntry { bits: bits as u64, typ: "imm".into(), value: Some(v) });
                            }
                            _ => {
                                entries.push(PoolEntry { bits: bits as u64, typ: "native".into(), value: None });
                            }
                        }
                        continue;
                    }
                    if legacy {
                        // ≤2.9：TypeBits=低7位；0/4=ref，1=imm，2/3=nothing
                        match bits & 0x7F {
                            0 | 4 => {
                                let v = read_ref_codec(codec, r)?;
                                entries.push(PoolEntry { bits: bits as u64, typ: "obj".into(), value: Some(v as i64) });
                            }
                            1 => {
                                let v = read_signed(r)?;
                                entries.push(PoolEntry { bits: bits as u64, typ: "imm".into(), value: Some(v) });
                            }
                            _ => {
                                entries.push(PoolEntry { bits: bits as u64, typ: "native".into(), value: None });
                            }
                        }
                        continue;
                    }
                    // 2.10+：behavior=(bits>>5)&7 ∈ 2..=4 → stub（无值）
                    let behavior = (bits >> 5) & 0x7;
                    if (2..=4).contains(&behavior) {
                        entries.push(PoolEntry { bits: bits as u64, typ: "stub".into(), value: None });
                        continue;
                    }
                    let typ = bits & 0xF;
                    if typ == 1 {
                        let v = read_ref_codec(codec, r)?;
                        entries.push(PoolEntry { bits: bits as u64, typ: "obj".into(), value: Some(v as i64) });
                    } else if typ == 0 {
                        let v = read_signed(r)?;
                        entries.push(PoolEntry { bits: bits as u64, typ: "imm".into(), value: Some(v) });
                    } else {
                        entries.push(PoolEntry { bits: bits as u64, typ: "native".into(), value: None });
                    }
                }
            }
            CStep::InstanceFields => {
                if profile.format.instance_legacy {
                    // ≤2.9：无 bitmap——每对象 1 字节 is_canonical + (nfo-1) 个纯 refs
                    let _ = r.read_u8().map_err(|e| format!("instance canon byte: {e:?}"))?;
                    let slots = meta.next_field_offset_in_words - 1;
                    let mut vals = Vec::with_capacity(slots as usize);
                    for j in 0..slots {
                        let v = read_ref_codec(codec, r)?;
                        vals.push(FieldVal::Ref { v, slot: j });
                    }
                    snap.instance_fields.insert(meta.start_ref + k, (meta.cid, vals));
                    continue;
                }
                let bitmap = if k == 0 {
                    let b = read_unsigned(r)?;
                    instance_bitmaps.insert(meta.start_ref, b);
                    if std::env::var("DART_AOT_DEBUG_CLASSES").is_ok() {
                        eprintln!(
                            "[dbg-map] cid={} nfo={} isize={} bitmap={:#x} slots={}",
                            meta.cid,
                            meta.next_field_offset_in_words,
                            meta.instance_size_in_words,
                            b,
                            meta.next_field_offset_in_words.saturating_sub(1)
                        );
                    }
                    b
                } else {
                    *instance_bitmaps.get(&meta.start_ref).unwrap_or(&0)
                };
                let slots = meta.next_field_offset_in_words - 1;
                let mut vals = Vec::new();
                for j in 0..slots {
                    if bitmap & (1u64 << (j + 1)) != 0 {
                        // ReadWordWith32BitReads = 2 × Raw<4>::Read，而 Raw<4>::Read 走
                        // Read32()=有符号变长（datastream.h），故 unboxed 槽恒为两个
                        // svarint（2.15-2.19 全版本一致，曾误判 2.15-2.17 为 4B raw）。
                        let v = r.read_word_32x2().map_err(|e| format!("instance word32x2: {e:?}"))?;
                        vals.push(FieldVal::Unboxed { v, slot: j });
                    } else {
                        let v = read_ref_codec(codec, r)?;
                        vals.push(FieldVal::Ref { v, slot: j });
                    }
                }
                snap.instance_fields.insert(meta.start_ref + k, (meta.cid, vals));
            }
            CStep::Code => {
                let nondef = meta.count - meta.deferred;
                let pinfos = snap.payload_infos.get_or_insert_with(Vec::new);
                if k == 0 {
                    snap.code_start_ref = Some(meta.start_ref);
                    // 3.13+：lazy_compile_index / unknown_dart_code_index（每簇一次）
                    for _ in 0..profile.format.code_leading_refs {
                        let _ = read_ref_codec(codec, r)?;
                    }
                }
                let payload_info = if k < nondef {
                    // ≤2.16 在 payload_info 前还有 text-offset delta（bare
                    // instructions 模式）：SDK previous_text_offset_ 为整个
                    // Deserializer（=整快照）级的累加和，entry_point =
                    // instr_base + 累计偏移。此处同步累积供地址层导出。
                    if profile.format.code_has_text_offset {
                        let delta = read_unsigned(r)?;
                        let tos = snap.text_offsets.get_or_insert_with(Vec::new);
                        let prev = tos.last().copied().unwrap_or(0);
                        tos.push(prev + delta);
                    }
                    read_unsigned(r)?
                } else {
                    0
                };
                pinfos.push(payload_info);
                for _ in 0..profile.format.code_refs {
                    let _ = read_ref_codec(codec, r)?;
                }
            }
            CStep::Emit(store) => {
                let start_ref = meta.start_ref;
                let need = |f: &CField, what: &str| -> Result<i64, String> {
                    gv(ctx, f).ok_or_else(|| format!("emit 引用未捕获字段 {what}"))
                };
                match store {
                    CStore::Functions { name_ref, owner_ref, sig_ref, code_index, kind_tag } => {
                        if std::env::var("DART_AOT_DEBUG_FUNCREF").is_ok() && k < 12 {
                            eprintln!(
                                "[dbg-funcref] k={k} ref={} pos={} name_ref={} owner_ref={} sig_ref={} code_idx={} kind={}",
                                start_ref + k, r.pos, gv(ctx, name_ref).unwrap_or(-999),
                                gv(ctx, owner_ref).unwrap_or(-999), gv(ctx, sig_ref).unwrap_or(-999),
                                gv(ctx, code_index).unwrap_or(-999), gv(ctx, kind_tag).unwrap_or(-999),
                            );
                        }
                        snap.functions.insert(start_ref + k, FunctionRec {
                            name_ref: need(name_ref, "name_ref")? as u64,
                            owner_ref: need(owner_ref, "owner_ref")? as u64,
                            code_index: need(code_index, "code_index")? as u64,
                            kind_tag: need(kind_tag, "kind_tag")?,
                        });
                    }
                    CStore::Classes { name_ref, library_ref, class_id, super_type_ref, next_field_off, type_arg_off, field_bitmap } => {
                        if std::env::var("DART_AOT_DEBUG_CLASSES").is_ok() && k < 300 {
                            eprintln!(
                                "[dbg-class] k={} pos={} ref={} class_id={} name_ref={} lib={} sup={}",
                                k, r.pos, start_ref + k, gv(ctx, class_id).unwrap_or(-1),
                                gv(ctx, name_ref).unwrap_or(-1), gv(ctx, library_ref).unwrap_or(-1),
                                gv(ctx, super_type_ref).unwrap_or(-1)
                            );
                        }
                        snap.classes.insert(start_ref + k, ClassRec {
                            name_ref: need(name_ref, "name_ref")? as u64,
                            library_ref: need(library_ref, "library_ref")? as u64,
                            class_id: need(class_id, "class_id")?,
                            super_type_ref: need(super_type_ref, "super_type_ref")? as u64,
                            next_field_off: need(next_field_off, "next_field_off")?,
                            type_arg_off: need(type_arg_off, "type_arg_off")?,
                            field_bitmap: need(field_bitmap, "field_bitmap")? as u64,
                        });
                    }
                    CStore::Libraries { name_ref, url_ref } => {
                        snap.libraries.insert(start_ref + k, LibraryRec {
                            name_ref: need(name_ref, "name_ref")? as u64,
                            url_ref: need(url_ref, "url_ref")? as u64,
                        });
                    }
                    CStore::PatchClass { wrapped } => {
                        snap.patch_classes.insert(start_ref + k, need(wrapped, "wrapped_class")? as u64);
                    }
                    CStore::TypeCid { type_cid } => {
                        snap.type_cids.insert(start_ref + k, need(type_cid, "type_cid")? as u64);
                    }
                    CStore::MapData { data_ref, used_ref } => {
                        snap.map_data.insert(
                            start_ref + k,
                            (meta.cid, need(data_ref, "data_ref")? as u64, need(used_ref, "used_ref")? as u64),
                        );
                    }
                    CStore::ArrayElements { ta, elems } => {
                        let ta_v = need(ta, "ta")? as u64;
                        let elems_v: Vec<u64> = lists
                            .get(*elems as usize)
                            .map(|l| l.iter().map(|v| *v as u64).collect())
                            .unwrap_or_default();
                        snap.array_elements.insert(start_ref + k, (ta_v, elems_v));
                    }
                }
            }
        }
    }
    Ok(())
}