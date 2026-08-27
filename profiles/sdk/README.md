# SDK Profile 库（profiles/sdk/）

每个文件 = 一份 `(Dart 版本, word_size=8, no-compressed-pointers)` 的 SDK Profile，
由本地工作区 `tools/sdk2profile.py`（不入库）从对应版本 SDK 源码机械生成（关键文件：`class_id.h`（≤2.0 在
`raw_object.h`）、`pointer_tagging.h`（≤2.0 同上）、`raw_object.h`、`clustered_snapshot.cc/.h`
（2.15 起称 `app_snapshot.cc/.h`）、`datastream.h`）。

## 时代划界（由事实决定）

| 时代 | Dart 版本 | 快照格式 | 本工具 |
|---|---|---|---|
| 现代 cluster | 2.15 – 3.7.2 | 现行 cluster 流；ref=ReadRefId（2.19+）；指令表在快照 ROData | **支持**（3.3.4 verified） |
| 早期 cluster | 2.0 – 2.14 | cluster 流同族；ref=ReadUnsigned；头字段 3→6 个演化；无指令表 data offset | **支持（对象层）**；函数地址受限于指令表位置 |
| 初代 cluster | 1.24 – 1.27 | cluster 流同族；ref=**带符号 varint**；头字段全部 signed；无指令表 | **支持（对象层）**，unverified |
| 前 cluster（raw_object_snapshot） | 0.x – 1.15 | `raw_object_snapshot.cc` 时代：逐 raw object 串流，非 cluster 格式；无 AOT 快照 | **不支持**：格式家族不同，需要第二个解析引擎；且该时代不存在 Flutter 产物 |

## 2026-08-17 更新：3.8–3.14 谱系实测

用官方 SDK 自编译 hello 样本对拍。结果：
- **verified 共 10 版**：3.0.0 / 3.3.4 / 3.7.2 / 3.8.3 / 3.9.4 / 3.10.9 / 3.11.6 / 3.12.2 / **3.13.0 / 3.14.0-95.1.beta**（样本实测；名字/Classes/pp/objs 全对）
- **3.13.0 / 3.14.0-95.1.beta（本轮收敛为 verified）**：六项新机制全部打通——① 单快照模式（kind=2、单 magic、`format.single_snapshot`）② 三段式符号（`symbols_alt`：`_kDartSnapshotData`/`_kDartSnapshotText`，指令段地址可用）③ LocalVarDescriptors/ContextScope 新簇 ④ **Closure 转 var**（3.13 起 fill=length+**3 固定 refs**（length_and_flags/hash/function）+length 个变长 refs）⑤ **Class 转 FixedSize alloc**（`format.class_alloc=fixed`）⑥ Error 家族五类进 AOT。**验证证据：函数入口地址与 nm 符号表 1174/1174（3.13）、1161/1161（3.14b）完全重合；class 表含全部预定义 + 用户类（Greeter）**。本轮两个关键修复：Closure fill 补 3 个固定 refs（此前 14 个闭包对象使 class 起点漂 47B → 全表错位）；Code 簇 fill 前导 2 refs（`lazy_compile_index`/`unknown_dart_code_index`，`format.code_leading_refs=2`，生成器按 `set_lazy_compile_index` 特征探测）
- 3.13 起容器从 ELF 变 **Mach-O dylib**（同一版本变更打包）
- 3.12+ class_id.h 采用 `CLASS_ID_LIST`/`CID()` 新枚举形态（生成器已兼容）

## 版本矩阵

| 文件 | ref 编码 | 头字段 | 状态 |
|---|---|---|---|
| `dart-3.3.4` | ref_id_128 | 5 | **verified**（a macOS Flutter app 全量对拍；生成器复现一致） |
| `dart-3.7.2` | ref_id_128 | 5 | **verified**（hello 样本；Greeter✓） |
| `dart-3.6.1 / 3.5.0` | ref_id_128 | 5 | **verified**（hello 样本；Greeter✓、530/524 具名类目） |
| `dart-3.4.0` | ref_id_128 | 5 | unverified（SIMD typed 移除 → predef 174；SDK 下载中） |
| `dart-3.0.0` | ref_id_128 | 5 | **verified**（hello 样本；r2 1005 函数、624 Classes） |
| `dart-3.13.0 / 3.14.0-95.1.beta` | ref_id_128 | 5 | **verified**（hello 样本；nm 地址 100% 重合；闭包/Code 新布局） |
| `dart-2.19.6` | ref_id_128 | 5 | **verified**（hello 样本；633 Classes、函数 1240 具名） |
| `dart-2.17.0` | unsigned_leb128 | 6（多 initial_field_table_len） | **verified**（hello 样本；nm 99.9%） |
| `dart-2.15.0` | unsigned_leb128 | 5（无 data offset → 地址降级） | **对象层 verified（2026-08-18 样本实证）**：Code fill 代差（前导 text-offset + 7 refs）+ 2.17 布局重映射，alloc 保持原生成 |
| `dart-2.14.4` | unsigned_leb128 | 5（无 data offset） | **对象层 verified（2026-08-18 样本实证）**；地址层不可用（无指令表头字段+strip 符号）。profile 由修复后的生成器重生成 |
| `dart-2.12.4` | unsigned_leb128 | 5（含 num_canonical_clusters） | **对象层 verified（2026-08-18 样本实证）**：簇头=裸 cid（2.12 源码 `intptr_t cid=ReadCid()`，无 canonical 位——canonical 由簇序决定；旧 profile 的 `cid_and_canonical` 使全簇 cid 右移 1 位错位）；kMessageMagic 信封两段式；Class 双段 15 refs（to_snapshot 锚点派生修复）；Code=[2uv+7R+sv] pre/post（deferred 只 7R+sv）。样本：ISO obj=14282 闭合、430+ 类名、strings 全解码。残余：argv 依赖变体 code 簇尾 3 字节欠读 |
| `dart-2.10.4` | unsigned_leb128 | 4（field_table_len） | **对象层 verified（2026-08-18 样本实证）**：legacy210 混合布局（16R Class + 9sv、Code=[sv+7R+sv]），样本闭合、类名含 Greeter |
| `dart-2.7.2` | unsigned_leb128 | 4（code_order_length） | **对象层 verified（2026-08-18 样本实证）**：老 era 结构（裸 cid 簇头、Code 仅 count、Type 双段计数、无 bitmap instance、typed rem{0,2}=var）全部转写，详见 artifacts/README |
| `dart-2.0.0` | unsigned_leb128 | 3 | unverified |
| `dart-1.24.3` | **signed_varint** | 3（全部 signed 读） | unverified，对象层 |

## 生成/新增版本

生成器与完整接入流程见本地工作区 `tools/`（`tools/NEW_VERSION.md`、`tools/sdk2profile.py`，均不入库）。

cid 锚点与 3.3.4 不同的版本会打印「差异」告警（正常现象）；有该版本样本后对拍
（首选锚点：num_objects 精确闭合），通过后把 status 改 verified。

## 实测样本状态（本地工作区 `dart/dart_samples/`，不入库；2026-08-17 快照）

hello world AOT/JIT 样本 ×8 版本的实测结果见 `dart/dart_samples/artifacts/README.md`：

- **3.0.0 / 3.3.4 / 3.7.2 = verified**（样本全量对拍；main/fib/Greeter.greet 名字精确）
- 2.17.0 / 2.19.6：refs 代差（PatchClass 2→3）、Class 双段与特类布局已按源码生成，但 **instance/typed 等其余簇仍代差 → 名字级未对齐**（引擎 fill 位置跟踪已定位，待下一轮 per-version 提取）
- 未验证版本导出前显式告警（防误导；以 verified 版本为准）
- 快照魔数扫描回退（[f5 f5 dc dc]）已实现：对 alineated 容器有效；dart2native 老 exe（2.7.2/2.14.4）内嵌布局特殊——回退释放但仍会漂（判为不支持）。裸 JIT 快照（1.24/2.0 官方 SDK 无 AOT）同样记录为不支持
- 实测修出的引擎 bug：容器魔数字节序；**3.4+ cluster 头 = 完整对象 tags**（cid=ClassIdTag::decode、canonical=bit1，`format.cluster_header=cid_tags`，生成器经 `ClassIdTag::decode` 出现自动探测，实测边界在 3.4）

## 已知边界（据实）

- 1.24–2.14 无「指令表 data offset」头字段 → 函数地址/r2/asm 自动降级（警告 + 仅对象层；
  地址数据在 AOT image/未序列化，需独立解析器才能补齐）。
- 早期版本 cluster 布局与 3.3.4 有代差（如 Function 字段集），生成器按共享基线+cid 重映射
  产出，需样本逐版验收；任何漂移引擎会以「无布局/alloc mismatch」显式报错。
- word_size=4 / compressed 组合：生成器加 `--word-size 4 --compressed` 重跑；runtime_offsets
  需对应构建产物（只影响 IL 注释）。

## 防陈旧机制（2026-08-18 增）

- 生成器写入 `_meta.generator_rev`（`GENERATOR_REV` 常量，任何影响输出的改动必须 +1）。
- 新鲜度校验脚本位于本地工作区 `scripts/check_profiles.sh`（不入库）：对每个
  `dart_profiles/sdk_src/<ver>` 用当前生成器再生成并与
  落盘 profile 对拍（保留 status），不一致即失败。当前 26/26 全绿。
- **历史债务**：2026-08-18 前多个落盘 profile 与生成器输出漂移（手调未回灌）。已触发全量
  重生成 + 收敛：修出 2 个真实生成器 bug（① 2.7 系 TypeParameter 无双段计数——引擎误读
  count2 致 drift；② 2.14 起 Code WriteAlloc 每对象写 state_bits=state_deferred 而非
  deferred_only，按源码探测区分于 2.10-2.12）。残余：2.15/2.17 重生成后 Greeter 缺失（class 簇起点前各 fill 已逐簇走査闭合，
  残余歧义在 class 段布局网格搜索距下一簇 +175B）；3.0 typed_first=114 已经源码坐实
  （旧档 113 为旧 profile bug，已重归档）。
