//! SDK Profile / Platform Profile 的 serde 结构与加载。
//!
//! 三层拆分（见 DART_AOT_UNIVERSAL_EXPORTER_DESIGN.md）：
//! - A 引擎（代码写死，本 crate 的 engine/）：变长编码、cluster 流遍历骨架、对象图、命名还原、导出 writer
//! - B SDK Profile（profiles/sdk/*.json）：class id 枚举、每 cid 的 cluster 布局（fill DSL）、
//!   tagging/alignment、runtime_offsets —— 随 Dart 版本 + word_size + compressed 变
//! - C Platform Profile（profiles/platform/*.json）：容器格式 + 符号名、寄存器映射、IL 模式、
//!   polymorphic 偏移 —— 随架构/OS 变

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

/// SDK Profile 自动识别（版本指纹 hash 命中 + 结构探针）
pub mod detect;

pub type JsonMap = serde_json::Map<String, serde_json::Value>;

// ------------------------------------------------------------------ SDK Profile

#[derive(Debug, Clone, Deserialize)]
pub struct Tagging {
    pub heap_object_tag: u64,
    pub object_alignment: u64,
    pub object_alignment_log2: u32,
    pub smi_mask: u64,
    pub smi_shift: u32,
    /// ClassIdTagPos / ClassIdTagMask（frida 常量 + 字符串 tags 解析）
    pub cid_tag_pos: u32,
    pub cid_tag_mask: u64,
    pub num_predefined_cids: u64,
}

/// 流头字段：名字（默认 unsigned）或带读写类型
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum HeaderField {
    Name(String),
    Typed { name: String, kind: String },
}

impl HeaderField {
    pub fn name(&self) -> &str {
        match self {
            HeaderField::Name(n) => n,
            HeaderField::Typed { name, .. } => name,
        }
    }
    pub fn is_signed(&self) -> bool {
        matches!(self, HeaderField::Typed { kind, .. } if kind == "signed")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AllocConfig {
    pub rodata_cids: Vec<u64>,
    pub var_cids: Vec<u64>,
    pub mint_cid: u64,
    pub code_cid: u64,
    pub class_cid: u64,
    pub instance_cid: u64,
    pub instance_min: u64,
    pub library_cid: u64,
    pub function_cid: u64,
    /// Type 簇 cid（≤2.9/2.10 双段双计数 alloc 用）
    #[serde(default)]
    pub type_cid: u64,
    /// TypeParameter 簇 cid（2.10 同样双段双计数）
    #[serde(default)]
    pub type_parameter_cid: u64,
    pub ffi_cids: Vec<u64>,
    pub canonical_table_cids: Vec<u64>,
    /// canonical 集合中「子集型」表（kAllCanonicalObjectsAreIncludedIntoSet=false）：
    /// alloc 的表布局多写一个 first_element 变长。2.13/2.14 仅 Type 簇；
    /// 2.15+ 起全部簇无条件写 first_element。
    #[serde(default)]
    pub canonical_subset_table_cids: Vec<u64>,
    /// alloc 只写 cid（无 count、无数据）的簇：2.13 WeakSerializationReference
    /// （WriteAlloc 仅 WriteCid，对象经 FinalizeWeak 从计数中剔除）。
    #[serde(default)]
    pub cid_only_alloc_cids: Vec<u64>,
    pub typed_data_first: u64,
    pub typed_data_count: u64,
    /// 每槽 cid 跨度：2.19+ = 4；2.15–2.17 = 3（class_id.h COMPILE_ASSERT 探测）
    #[serde(default = "default_typed_stride")]
    pub typed_data_stride: u64,
    /// elem_widths[slot] = 字节宽；cid = first + slot*4 + rem
    pub typed_data_elem_widths: Vec<u64>,
    pub typed_data_var_rem: Vec<u64>,
    pub typed_data_view_rem: Vec<u64>,
    pub string_cid: u64,
    pub one_byte_string_cid: u64,
    pub two_byte_string_cid: u64,
}

// ------------------------------------------------------------------ fill DSL

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum LoopTimes {
    /// 循环次数 = alloc 阶段 lengths[k]（长度数组型对象）
    Named(String),
    Const(u64),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum FieldSource {
    Alias(String),
    Builtin { builtin: String },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Step {
    /// 读 n 个 ref-id；aliases 按序捕获（短于 n 只捕获前部，null 跳过）
    Refs {
        n: usize,
        #[serde(default)]
        aliases: Vec<Option<String>>,
        #[serde(default)]
        collect: Option<String>,
    },
    Uvarint {
        #[serde(default)]
        alias: Option<String>,
        #[serde(default)]
        collect: Option<String>,
        /// 可选变换："shr4_and_mask"（Type 的 type_class_id = (flags>>4)&cid_tag_mask）
        #[serde(default)]
        transform: Option<String>,
    },
    Svarint {
        #[serde(default)]
        alias: Option<String>,
        #[serde(default)]
        collect: Option<String>,
    },
    Byte {
        #[serde(default)]
        alias: Option<String>,
        #[serde(default)]
        collect: Option<String>,
    },
    /// 读固定 4 字节小端 uint32（2.15/2.16/2.17 Function 的 packed_fields_/kind_tag_）
    U32 {
        #[serde(default)]
        alias: Option<String>,
        #[serde(default)]
        collect: Option<String>,
    },
    /// 读一个 varint 并累加到快照级 text_offsets（裸指令 legacy Code 簇：code 对象
    /// 前导 text-offset delta，2.10-2.14 用旧式显式 Code DSL 未接 `Code` 步骤时的地址层捕获）。
    /// signed=true：delta 用有符号变长读（2.10 特例，其余为 unsigned）。
    TextOffset {
        #[serde(default)]
        signed: bool,
    },
    /// 子循环：times = "lengths"（用 alloc lengths[k]）或常量
    Loop { times: LoopTimes, steps: Vec<Step> },
    /// 条件执行：on=捕获字段名；lt/ge 数域、bit 位测试（任一命中即执行 then）；
    /// 不命中时写入 set_default 的默认捕获值；
    /// 可选 else 步骤序列（老版 Class 的「!IsInternalVMdefinedClassId 跳过两值」形态）
    Cond {
        on: String,
        lt: Option<u64>,
        ge: Option<u64>,
        #[serde(default)]
        bit: Option<u32>,
        then: Vec<Step>,
        #[serde(default, rename = "else")]
        else_steps: Vec<Step>,
        #[serde(default)]
        set_default: HashMap<String, i64>,
    },
    /// 跳过 lengths[k] * elem_width(cid) 原始字节（TypedData payload）
    SkipRawElemWidth,
    /// 对齐填充：跳到 position % n == 0（≤2.9 ExternalTypedData 的
    /// kDataSerializationAlignment=8 对齐）
    SkipAlign { n: u64 },
    SkipConst { n: u64 },
    /// 特殊：ObjectPool（子格式 = length + 逐 entry bits 派遣）
    #[serde(rename = "objectpool")]
    ObjectPool,
    /// 特殊：Instance 的 bitmap + nfo-1 个 slot 循环
    InstanceFields,
    /// 特殊：Code 的 payload_info（k<nondef）+ 6 refs
    Code,
    /// 产出记录到指定表
    Emit { store: String, fields: HashMap<String, FieldSource> },
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClusterLayout {
    pub steps: Vec<Step>,
}

/// 老版 Class 簇：pre（预定义段）与 post（常规段）布局不同
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum StepsSpec {
    Single { steps: Vec<Step> },
    Split { pre: Vec<Step>, post: Vec<Step> },
}

impl StepsSpec {
    pub fn pre(&self) -> &[Step] {
        match self {
            StepsSpec::Single { steps } => steps,
            StepsSpec::Split { pre, .. } => pre,
        }
    }
    pub fn post(&self) -> &[Step] {
        match self {
            StepsSpec::Single { steps } => steps,
            StepsSpec::Split { post, .. } => post,
        }
    }
}

/// 快照格式级差异（引擎的版本开关；见 docs/PROFILES.md）
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FormatConfig {
    /// "ref_id_128"（2.19+，大端 7bit 分组 +128）| "unsigned_leb128"（≤2.17）
    pub ref_encoding: String,
    /// "snapshot_rodata"（默认）| "image"（2.15：指令表在 AOT image 而非快照流）
    pub instructions_table_source: String,
    /// "cid_and_canonical"（≤3.5：cid=值>>1, canonical=值&1）
    /// | "cid_tags"（3.6+：cluster 头为完整对象 tags，cid=ClassIdTag::decode，canonical=bit1）
    pub cluster_header: String,
    /// 3.13+：VM/ISO 合并成单一快照（数据段只有一个 magic/头）
    #[serde(default)]
    pub single_snapshot: bool,
    /// "pre_ids"（≤3.12：Class alloc 有预定义 id 前缀段）| "fixed"（3.13+：ReadAllocFixedSize）
    #[serde(default)]
    pub class_alloc: String,
    /// 3.13+：Code 簇 fill 在逐对象循环前有 2 个前导 refs（lazy_compile_index/
    /// unknown_dart_code_index），≤3.12 无
    #[serde(default)]
    pub code_leading_refs: u64,
    /// ≤2.14：string 数据分散在 string/one_byte/two_byte 三个 cid 各自的 ROData
    /// 簇（每个都带 rodata offsets，引擎对三个 cid 都做 offset 解码）；
    /// 2.15+ 全部集中在 string_cid 一个簇（单个簇内按对象 tags 区分单/双字节）
    #[serde(default)]
    pub string_clusters_separate: bool,
    /// ≤2.9：Code 簇 alloc 只有 count（无 state_bits/deferred）
    /// "state_deferred"（2.10+）/ "count_only"（≤2.9）
    #[serde(default = "default_code_alloc")]
    pub code_alloc: String,
    /// ≤2.9：Type 簇 alloc 为双段双计数（canonical 段 + 常规段各一个 count）
    #[serde(default)]
    pub type_dual_count: bool,
    /// ≤2.9/2.10：instance 无 bitmap——每对象 1 字节 is_canonical + (nfo-1) 个纯 refs
    #[serde(default)]
    pub instance_legacy: bool,
    /// 2.10 特例：instance alloc 只读 nfo（无 instance_size_in_words，样本实证）
    #[serde(default)]
    pub instance_alloc_nfo_only: bool,
    /// ≤2.9：ObjectPool entry 位域为 TypeBits=低7位，类型映射 0=ref/1=imm/4=nativedata=ref
    /// （2.10+ TypeBits=低4位且映射不同）——pool 条目解析的 era 开关
    #[serde(default)]
    pub objectpool_legacy: bool,
    /// 2.10–3.1：ObjectPool entry 位域 = TypeBits 位0-6（0=TaggedObject/1=Immediate/
    /// 2+=Native）+ 位7 Patchable；3.3+ 才改为 SnapshotBehavior 位5-7 + 低4位类型。
    #[serde(default)]
    pub objectpool_type_low7: bool,
    /// 3.2.x 特例：EntryType 顺序交换（0=Immediate/1=TaggedObject），TypeBits 仍是
    /// 位0-6 + 位7 Patchable（object.h 复用 ObjectPoolBuilderEntry::TypeBits 实证）。
    #[serde(default)]
    pub objectpool_type_low7_swapped: bool,
    /// Code 簇 fill 每对象 refs 数（内建 Code 步骤用；2.15=7 多 compressed_stackmaps，
    /// 其余 6）
    #[serde(default = "default_code_refs")]
    pub code_refs: u64,
    /// ≤2.16：Code fill 的 ReadInstructions 前导 text-offset uvarint
    /// （2.17+ 只有 payload_info 一个 uvarint）
    #[serde(default)]
    pub code_has_text_offset: bool,
    /// 2.18.x 专属特殊处理：Class 簇 fill 起点修正（字节）。2.18 为过渡版，紧邻
    /// Class 的前置簇（instance 等）多读 2 字节致 Class 簇整体偏移 2 字节 → 类名全失。
    /// 逐字节对拍：Class 真起点在引擎当前起点前 2 字节，修正后类别可全部解析
    /// （Greeter/JsonCodec 等类名恢复）。仅 2.18 设 -2，其余版本缺省 0。
    #[serde(default)]
    pub class_fill_adj: i64,
    /// 2.18.x 专属特殊处理：Code 簇 fill 起点修正（字节）。2.18 的 ISO Code 簇
    /// 前导多读 4 字节，致其后的 Function/Class 簇连锁偏移（函数名与类名全失）。
    /// 修正 -4 后 greet 等用户函数名/入口恢复（与 class_fill_adj=-2 叠加）。仅 2.18 设 -4。
    #[serde(default)]
    pub code_fill_adj: i64,
    /// 过渡版（2.16/2.18 等）函数名不在 fill ref 时，按入口地址回填 ELF 函数符号名。
    /// 仅对 name-fill 失真的版本开启（其余版本 name 解析正确，开启会改动受验存档）。
    #[serde(default)]
    pub elf_name_backfill: bool,
}

fn default_code_refs() -> u64 {
    6
}

fn default_code_alloc() -> String {
    "state_deferred".to_string()
}

fn default_typed_stride() -> u64 { 4 }

impl Default for FormatConfig {
    fn default() -> Self {
        FormatConfig {
            ref_encoding: "ref_id_128".into(),
            instructions_table_source: "snapshot_rodata".into(),
            cluster_header: "cid_and_canonical".into(),
            single_snapshot: false,
            class_alloc: "pre_ids".into(),
            code_leading_refs: 0,
            string_clusters_separate: false,
            code_alloc: "state_deferred".into(),
            type_dual_count: false,
            instance_legacy: false,
            instance_alloc_nfo_only: false,
            objectpool_legacy: false,
            objectpool_type_low7: false,
            objectpool_type_low7_swapped: false,
            code_refs: 6,
            code_has_text_offset: false,
            class_fill_adj: 0,
            code_fill_adj: 0,
            elf_name_backfill: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SdkProfile {
    /// 标识：如 "dart/3.3.4"
    pub abi: String,
    /// 快照格式级差异（ref 编码 / 指令表来源）
    #[serde(default)]
    pub format: FormatConfig,
    /// verified=样本对拍通过；unverified=布局数据可能未对齐（导出前显式告警）
    #[serde(default)]
    pub status: String,
    pub word_size: u64,
    pub compressed_pointers: bool,
    pub tagging: Tagging,
    /// 快照流头字段读取顺序（名 → Header map）；
    /// 兼容两种形态：'"name"' 或 '{"name": ..., "kind": "unsigned"|"signed"}'
    #[serde(default)]
    pub header_fields: Vec<HeaderField>,
    pub full_aot_kind: i64,
    pub object_start_alignment: u64,
    pub alloc: AllocConfig,
    /// cid -> fill 布局（key 为十进制 cid 字符串；值可为单段或 Class 双段）
    pub cluster_layouts: HashMap<String, StepsSpec>,
    /// offset 名 → 字节值（十进制）
    pub runtime_offsets: HashMap<String, u64>,
    /// frida 常量表：[["ClassIdTagPos", 12], ...]
    pub frida_cid_constants: Vec<(String, String)>,
    /// frida 特殊类布局（有偏移的预定义类），保持 JSON 键序输出
    pub frida_special_layouts: JsonMap,
    /// frida Classes 数组里带 lenOffset/dataOffset 的整数 TypedData cid
    #[serde(default)]
    pub frida_int_typed_cids: Vec<u64>,
    /// cid -> 预定义类标准名（稀疏，class_id.h 枚举；TypedData 系列含展开名）
    pub class_id_names: HashMap<String, String>,
}

impl SdkProfile {
    pub fn layout_for(&self, cid: u64) -> Option<&StepsSpec> {
        self.cluster_layouts.get(&cid.to_string())
    }

    pub fn typed_data_slot(&self, cid: u64) -> Option<u64> {
        let a = &self.alloc;
        if cid >= a.typed_data_first && cid < a.typed_data_first + a.typed_data_count {
            Some((cid - a.typed_data_first) / a.typed_data_stride)
        } else {
            None
        }
    }

    pub fn typed_data_rem(&self, cid: u64) -> Option<u64> {
        let a = &self.alloc;
        if cid >= a.typed_data_first && cid < a.typed_data_first + a.typed_data_count {
            Some((cid - a.typed_data_first) % a.typed_data_stride)
        } else {
            None
        }
    }

    pub fn elem_width(&self, cid: u64) -> u64 {
        self.typed_data_slot(cid)
            .and_then(|s| self.alloc.typed_data_elem_widths.get(s as usize))
            .copied()
            .unwrap_or(1)
    }

    pub fn is_var_kind(&self, cid: u64) -> bool {
        let a = &self.alloc;
        a.var_cids.contains(&cid)
            || self
                .typed_data_rem(cid)
                .map(|r| a.typed_data_var_rem.contains(&r))
                .unwrap_or(false)
    }

    pub fn is_view_kind(&self, cid: u64) -> bool {
        self.typed_data_rem(cid)
            .map(|r| self.alloc.typed_data_view_rem.contains(&r))
            .unwrap_or(false)
    }

    /// 对应参考实现 alloc_kind()：fixed / var / rodata / mint / code /
    /// class / instance / library / function
    pub fn alloc_kind(&self, cid: u64) -> &'static str {
        let a = &self.alloc;
        if a.rodata_cids.contains(&cid) {
            "rodata"
        } else if self.is_var_kind(cid) {
            "var"
        } else if cid == a.mint_cid {
            "mint"
        } else if cid == a.code_cid {
            "code"
        } else if cid == a.class_cid {
            "class"
        } else if cid == a.instance_cid || a.ffi_cids.contains(&cid) || cid >= a.instance_min {
            "instance"
        } else if cid == a.library_cid {
            "library"
        } else if cid == a.function_cid {
            "function"
        } else {
            "fixed"
        }
    }

    pub fn offset(&self, name: &str) -> u64 {
        *self.runtime_offsets.get(name).unwrap_or(&0)
    }

    /// 老版本（≤2.17）ref 为无符号 LEB128
    pub fn ref_is_legacy(&self) -> bool {
        self.format.ref_encoding == "unsigned_leb128"
    }

    /// 指令表不可从快照流表头解码（非 snapshot_rodata）。
    /// 三态：snapshot_rodata（2.17+，表头带 rodata_offset）/
    /// code_text_offsets（2.15-2.16 bare instructions，入口=Code 簇 text-offset 累加）/
    /// none（更早版本）。本方法仅用于告警分流。
    pub fn instr_table_in_image(&self) -> bool {
        self.format.instructions_table_source != "snapshot_rodata"
    }
}

// ------------------------------------------------------------------ Platform Profile

#[derive(Debug, Clone, Deserialize)]
pub struct SymbolNames {
    pub vm_data: String,
    pub isolate_data: String,
    pub isolate_instructions: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ContainerConfig {
    pub kind: String, // "macho" | "elf" | "pe"
}

#[derive(Debug, Clone, Deserialize)]
pub struct PlatformProfile {
    pub name: String,
    pub arch: String, // "arm64" | "x64" | "arm" | "riscv"
    pub endianness: String,
    pub container: ContainerConfig,
    pub symbols: SymbolNames,
    /// 备用符号集（如 Dart 3.13 单快照的三段式 _kDartSnapshotData/_Text）：
    /// 主符号集缺任一符号时整体回退尝试
    #[serde(default)]
    pub symbols_alt: Option<SymbolNames>,
    /// IL/反汇编用寄存器角色："thr" -> "x26" 等
    pub registers: HashMap<String, String>,
    /// 反汇编 op_str 重写别名（x29→fp ...），用于贴近 blutter 输出
    pub register_aliases: HashMap<String, String>,
    /// 不能作为对象字段基址的固定角色寄存器名
    pub non_field_base: Vec<String>,
    pub polymorphic_entry_offset_aot: i64,
    /// frida 模板重写：HeapAddressReg / compressed 常量
    pub frida_heap_address_reg: String,
    /// r2 addNames.r2 的 app.base：默认取容器 text 段 VM 地址
    #[serde(default)]
    pub r2_app_base: Option<String>,
    /// 验证状态："verified" | "unverified"
    #[serde(default)]
    pub status: String,
}

// ------------------------------------------------------------------ 内嵌 profile

pub const SDK_PROFILE_3_3_4: &str = include_str!("../../profiles/sdk/dart-3.3.4-w64-no-compressed.json");
pub const PLATFORM_MACHO_ARM64: &str = include_str!("../../profiles/platform/macho-arm64.json");

/// 全部 SDK Profile 内嵌（abi, JSON）。声明序即自动识别同分决胜序：
/// verified 系在前（现代目标优先），其次 objects 层、过渡版，unsupported 垫底。
pub const SDK_PROFILES: &[(&str, &str)] = &[
    ("dart/2.15.0", include_str!("../../profiles/sdk/dart-2.15.0-w64-no-compressed.json")),
    ("dart/2.17.0", include_str!("../../profiles/sdk/dart-2.17.0-w64-no-compressed.json")),
    ("dart/3.0.0", include_str!("../../profiles/sdk/dart-3.0.0-w64-no-compressed.json")),
    ("dart/3.2.0", include_str!("../../profiles/sdk/dart-3.2.0-w64-no-compressed.json")),
    ("dart/3.3.4", include_str!("../../profiles/sdk/dart-3.3.4-w64-no-compressed.json")),
    ("dart/3.4.0", include_str!("../../profiles/sdk/dart-3.4.0-w64-no-compressed.json")),
    ("dart/3.5.0", include_str!("../../profiles/sdk/dart-3.5.0-w64-no-compressed.json")),
    ("dart/3.6.1", include_str!("../../profiles/sdk/dart-3.6.1-w64-no-compressed.json")),
    ("dart/3.7.2", include_str!("../../profiles/sdk/dart-3.7.2-w64-no-compressed.json")),
    ("dart/3.8.3", include_str!("../../profiles/sdk/dart-3.8.3-w64-no-compressed.json")),
    ("dart/3.9.4", include_str!("../../profiles/sdk/dart-3.9.4-w64-no-compressed.json")),
    ("dart/3.10.9", include_str!("../../profiles/sdk/dart-3.10.9-w64-no-compressed.json")),
    ("dart/3.11.6", include_str!("../../profiles/sdk/dart-3.11.6-w64-no-compressed.json")),
    ("dart/3.12.2", include_str!("../../profiles/sdk/dart-3.12.2-w64-no-compressed.json")),
    ("dart/3.13.0", include_str!("../../profiles/sdk/dart-3.13.0-w64-no-compressed.json")),
    ("dart/3.14.0-95.1.beta", include_str!("../../profiles/sdk/dart-3.14.0-95.1.beta-w64-no-compressed.json")),
    ("dart/2.7.2", include_str!("../../profiles/sdk/dart-2.7.2-w64-no-compressed.json")),
    ("dart/2.10.4", include_str!("../../profiles/sdk/dart-2.10.4-w64-no-compressed.json")),
    ("dart/2.12.4", include_str!("../../profiles/sdk/dart-2.12.4-w64-no-compressed.json")),
    ("dart/2.13.4", include_str!("../../profiles/sdk/dart-2.13.4-w64-no-compressed.json")),
    ("dart/2.14.4", include_str!("../../profiles/sdk/dart-2.14.4-w64-no-compressed.json")),
    ("dart/2.16.2", include_str!("../../profiles/sdk/dart-2.16.2-w64-no-compressed.json")),
    ("dart/2.18.1", include_str!("../../profiles/sdk/dart-2.18.1-w64-no-compressed.json")),
    ("dart/2.19.6", include_str!("../../profiles/sdk/dart-2.19.6-w64-no-compressed.json")),
    ("dart/1.24.3", include_str!("../../profiles/sdk/dart-1.24.3-w64-no-compressed.json")),
    ("dart/2.0.0", include_str!("../../profiles/sdk/dart-2.0.0-w64-no-compressed.json")),
];

/// 解析后的注册表（惰性，一次）
static SDK_REGISTRY: OnceLock<Vec<(String, SdkProfile)>> = OnceLock::new();

pub fn sdk_registry() -> &'static [(String, SdkProfile)] {
    SDK_REGISTRY.get_or_init(|| {
        SDK_PROFILES
            .iter()
            .filter_map(|(abi, json)| parse_sdk(json).ok().map(|p| ((*abi).to_string(), p)))
            .collect()
    })
}

/// 版本指纹表：snapshot version hash（32 hex）→ profile abi。
/// 由 tools/gather_version_hashes.py 从本地样本生成（样本工作区不入库）。
pub const VERSION_HASHES: &str = include_str!("../../profiles/sdk/version_hashes.json");

static HASH_TO_ABI: OnceLock<HashMap<String, String>> = OnceLock::new();

pub fn abi_for_hash(hash: &str) -> Option<String> {
    let m = HASH_TO_ABI.get_or_init(|| serde_json::from_str(VERSION_HASHES).unwrap_or_default());
    m.get(hash).cloned()
}

pub fn parse_sdk(json: &str) -> Result<SdkProfile, String> {
    serde_json::from_str(json).map_err(|e| format!("SDK profile 解析失败: {e}"))
}

pub fn parse_platform(json: &str) -> Result<PlatformProfile, String> {
    serde_json::from_str(json).map_err(|e| format!("平台 profile 解析失败: {e}"))
}