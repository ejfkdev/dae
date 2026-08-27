# fill DSL & Profile 规范

引擎（`src/engine/`）跨 Dart 版本/平台不变；一切随版本/平台变化的数据都在 `profiles/` 的 JSON 里。
本文件是这两类配置的规范，也是「新增一个 Dart 版本/新平台时只改配置」的契约。

## 1. SDK Profile（`profiles/sdk/*.json`）

标识为 `(Dart 版本, word_size, compressed_pointers)`。`profiles/sdk/` 内 26 个版本
（1.24.3 → 3.14β）**全部编译进二进制**：`dae` 运行时按快照版本指纹（32B hash，
见 `version_hashes.json`）精确命中，未命中时对嵌入版本做结构探针 + fill 决胜
（见 `src/profile/detect.rs`）。全量对拍基准版本为 `dart-3.3.4-w64-no-compressed.json`
（a macOS Flutter app / arm64 / 3.3.4 / 无压缩指针 / --obfuscate 全量对拍通过）。

顶层字段（`SdkProfile`，serde 结构见 `src/profile/mod.rs`）：

| 字段 | 含义 |
|---|---|
| `abi` | 版本标识（文档用） |
| `word_size` / `compressed_pointers` | 影响 frida 常量与 runtime offsets |
| `tagging` | heap_object_tag / object_alignment(_log2) / smi_mask / smi_shift / cid_tag_pos / cid_tag_mask / num_predefined_cids |
| `header_fields` | 快照流头字段读取顺序（名字 → Header map） |
| `full_aot_kind` / `object_start_alignment` | kind=3（Snapshot::kFullAOT）；data_image 对齐 64 |
| `alloc` | 分配阶段分类（见下） |
| `cluster_layouts` | 每 cid 的 fill 布局（fill DSL，见 §3） |
| `runtime_offsets` | asm IL 用的对象布局偏移（thread_field_table_values / array_data_minus_tag 等） |
| `frida_cid_constants` | `blutter_frida.js` 头部常量（值原样输出；ClassIdTagMask 用字符串 "0xfffff" 保持原型） |
| `frida_special_layouts` | frida Classes 数组特殊类条目（bool/int/String/List/Map/Closure/Object 的静态名+偏移；键序即输出序） |
| `frida_int_typed_cids` | 带 lenOffset/dataOffset 的 8 个整数 TypedData cid |
| `class_id_names` | cid → 预定义类名（稀疏 map，来自 class_id.h 枚举 + TypedData 展开名） |
| `typed_data_names` | 14 个 TypedData 基类名（预留） |

### alloc 分类

| 键 | 含义 |
|---|---|
| `rodata_cids` | ROData 类（`{23,24,25,92,93,94}`）：alloc 读 delta 偏移，fill 空 |
| `var_cids` | 变长类（`{17,22,27,28,29,46,66,89,90}`）：alloc 读 count 个长度 |
| `mint_cid`(60) / `code_cid`(18) / `class_cid`(5) / `instance_cid`(44) / `library_cid`(13) / `function_cid`(7) | 特殊 alloc 段 |
| `instance_min`(176) / `ffi_cids` | instance alloc（先读 nfo/isize 两个 svarint） |
| `canonical_table_cids` | canonical=1 时额外读 canonical table |
| `typed_data_first/count/elem_widths/var_rem/view_rem` | TypedData 分类：rem=(cid-first)%4 ∈ var_rem{0,2} → 变长；view_rem{1,3} → view |
| `string_cid`(92) / `one_byte_string_cid`(93) / `two_byte_string_cid`(94) | 字符串解码 |

## 2. Platform Profile（`profiles/platform/*.json`）

表 `(容器, 架构)`：`macho/elf/pe × arm64/x64/…`。字段（`PlatformProfile`）：

| 字段 | 含义 |
|---|---|
| `container.kind` | macho / elf / pe（决定解析器） |
| `symbols` | 三个入口符号名（`_kDartVmSnapshotData` 等，跨平台同名） |
| `registers` | IL/反汇编用角色寄存器（thr/pp/null/barrier/fp/sp/lr/code_reg…） |
| `register_aliases` | op_str 重写别名表（x29→fp 等，对齐 blutter 输出风格） |
| `non_field_base` | 不能作为对象字段基址的固定角色寄存器 |
| `polymorphic_entry_offset_aot` | monomorphic 入口偏移（arm64 AOT = 24） |
| `frida_heap_address_reg` | frida 模板 HeapAddressReg 重写值 |
| `status` | verified / unverified（当前只有 macho-arm64 是 verified） |

## 3. fill DSL（`cluster_layouts[<cid>].steps`）

步骤列表逐对象（`k = 0..count`）解释执行，捕获进 per-object ctx（键值表）与 collect 列表。
`alloc` 阶段的产物按 `times:"lengths"` 引用。

### 原子读取

| op | 字段 | 语义 |
|---|---|---|
| `refs` | `n`、`aliases`(按序捕获名，null 跳过)、`collect`(n=1 时把值追加进列表名) | 读 n 个 ref-id |
| `uvarint` | `alias` / `collect` / `transform:"shr4_and_mask"` | ReadUnsigned；transform 为 Type 的 `(flags>>4)&cid_tag_mask` |
| `svarint` | `alias` / `collect` | Read\<T\> 有符号变长 |
| `byte` | `alias` / `collect` | 1 字节 |
| `skip_raw_elem_width` | — | 跳过 `lengths[k] * elem_width(cid)` 原始字节（TypedData） |
| `skip_const` | `n` | 跳过 n 字节 |

### 结构

| op | 字段 | 语义 |
|---|---|---|
| `loop` | `times` = `"lengths"`（alloc 长度）或常量；`steps` | 子循环 |
| `cond` | `on`(已捕获字段)、`lt`/`ge` 数域、`then`；`set_default`(不命中时写入的默认捕获) | 条件执行（Class 的 top-level 判空 bitmap 用） |
| `objectpool` | — | 特殊：length + 逐 entry bits 派遣（捕获 pp.txt 条目） |
| `instance_fields` | — | 特殊：cluster 级 bitmap + nfo-1 个 slot（ref 或 word32x2） |
| `code` | — | 特殊：payload_info（k\<nondef 才读）+ 6 refs |
| `emit` | `store`、`fields`（记录字段名 → alias 名 / `{"builtin":"cid"|"ref"}`） | 产出记录 |

内置布局（无需在 JSON 声明）：string 类（cid==string_cid，按 rodata offsets 解码）、rodata/mint（fill 空）、
instance 类（对应 `instance_fields` 步骤）、TypedData 与 View（原子 skip / 3 refs + 2 svarint）。

### emit store 表

| store | 记录字段 | 产出 |
|---|---|---|
| `functions` | name_ref, owner_ref, code_index, kind_tag | 函数表 |
| `classes` | name_ref, library_ref, class_id, super_type_ref, next_field_off, type_arg_off, field_bitmap | 类表 |
| `libraries` | name_ref, url_ref | 库表 |
| `patch_classes` | wrapped_class | PatchClass → 被包装类 |
| `type_cids` | type_cid | Type 对象的 class id |
| `map_data` | data_ref, used_ref（cid 自动取 cluster cid） | ConstMap/ConstSet |
| `array_elements` | ta, elems（collect 列表） | Array/ImmutableArray |

## 4. 容错与校验

- alloc 结束后校验 `next_ref - 1 == num_objects`，不等则告警（对应参考实现 alloc mismatch）。
- 某 cid 的流中出现 >60000 视为漂移，停止解析并告警。
- fill 遇到无布局的 cid 直接报错并给出「往 cluster_layouts 里加」的提示（参考实现是静默中断，这里选择显式失败）。
- 引擎对每条 emit 的未捕获字段报错（缺 `set_default` 的 cond 默认值是最常见原因）。