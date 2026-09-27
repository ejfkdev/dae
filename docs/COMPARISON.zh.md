# dae vs aotopsy：实测对照

两个工具都解析 Dart AOT 快照、都产出伪代码。这份文档记录的是：把它们指向**同一个文件**、
用**同一套判据**量出来的结果。

复现（脚本在 `testing/`，不入库）：

```bash
python3 testing/compare_aotopsy.py <libapp.so> [out_root]
```

脚本按各自默认用法跑两个工具，然后量：地址覆盖、与 ELF `.symtab` 的命名一致率（唯一外部真值）、
`dart analyze` 错误数、还有多少函数带着 `goto`、内联了多少对象池字面量、以及耗时。

## 判据（两边都不偏袒）

- **同一份输入文件**，谁都不做预处理。
- **命名用同一套归一化**：库哈希后缀（`@0150898`）、结尾的 `_<十进制序号>`、纯数字 token、
  以及方言词 `Precompiled_` / `init` / `new` 两边都剥掉；然后**真值名字的每个 token 都要能在
  工具的名字里找到**。两个工具各自用**自己的**方言规则量时都会更高（dae 的门禁
  `tests/ground_truth.rs` 是 89.4%（六份语料；加入 `hello_2.18.1`/`2.19.6`/`3.0.0` 之前是
  90.6%（三份）——下降是样本变宽变难的分母效应，不是退步：单看 `hello_2.19.6`，一致的名字从
  558 涨到 1 081；aotopsy 的 README 是 90.2%）——统一规则下都更低，这是预期内的。
- **可编译性用 `dart analyze`**，只数 `error`，并区分语法类与语义类。aotopsy 的 README 说
  "100% valid Dart"，其判据是"每个函数都能**解析**"（`TestDecompileQualityCorpus`），
  所以下面的语义列不构成对它那句话的反驳，而是另一个问题：产物能不能**过分析**。
- aotopsy 没有结构化输出的开关，所以"结构化"对两边用同一个办法量：剥掉注释后函数体里出现
  goto 就算未结构化——dae 是 `gotoLabel(0x..)`，aotopsy 是 `goto block_N;` / `label:`。

## 结果（三个 x64 ELF 语料，同一批文件）

| | T4_blank | | hello_2.15.0 | | H_minimal_compact | |
|---|---|---|---|---|---|---|
| | **dae** | aotopsy | **dae** | aotopsy | **dae** | aotopsy |
| 有地址的函数 | 1434 | 1434 | 1418 | 1418 | 1434 | 1434 |
| …其中在 `.symtab` 里 | 1434 | 1434 | 1418 | 1418 | 1434 | 1434 |
| 命名一致率（统一规则） | 83.8% | 87.1% | 81.0% | 84.6% | 83.5% | 87.2% |
| `dart analyze` 语法错 | **0** | 5233 | **0** | 5380 | **0** | 5233 |
| `dart analyze` 语义错 | **0** | 65109 | **0** | 62720 | **0** | 65081 |
| 含 goto 的函数 | **12.2%** | 64.3% | **9.3%** | 63.4% | **12.2%** | 64.3% |
| 内联池字面量 | 318 | 298 | 502 | 295 | 315 | 295 |
| 耗时 | **0.38s** | 2.90s | **0.33s** | 2.61s | **0.39s** | 2.87s |

函数数之所以相等，是这次对照**改出来的**（见下）；改之前是 1258 vs 1434。

## dae 领先的地方

- **产物能编译**：同一文件上 aotopsy 约 7 万条 `dart analyze` 错误（语法类 5.2k：未声明的寄存器、
  不能解析的 `goto` 目标；语义类 65k：未声明的标识符/函数），dae 是 0。这对不上不是文字游戏——
  dae 为此做了每文件的伪运行时前导与机器写法改写，见 [`DECOMPILER.zh.md`](DECOMPILER.zh.md)。
- **控制流结构化**：dae 9–12% 的函数留着 `goto`，aotopsy 是 63–64%。aotopsy 的产物里自己写明了：
  `goto block_2;` + `block_2:;` 标签，还有
  `// --- code omitted by the structured walk, shown verbatim ---`。
- **速度**：同一文件约 7 倍（0.4s vs 2.9s）。
- **池常量**：这几个语料上 dae 内联得更多（318 vs 298、502 vs 295）；在 Flutter macOS 应用上是 1922 条。

## aotopsy 领先的地方

- **字段访问是重写而不是注解**：aotopsy 打印 `local_16.values_14b94 = 0;`——基址、点、字段名。
  dae 现在用**同一个来源**恢复出同样的名字（读 `MintValues[HostOffset] × wordSize`，与 aotopsy 的
  `class_layouts.go` 一模一样，另外补了隐式访问器名这条路），但挂成带归属的注释：
  `mem(local_16, 0x17) /* _FutureListener.result (off 0x18) */`。要写成 `local_16.result` 得知道
  基址的**类型**——aotopsy 靠全程序推断（`typetrack`），dae 还没有；没那一步就断言类型属于编造。
  所以：名字一致、呈现不同，而 dae 这半边是诚实的。
- **类型测试 stub 的命名**：aotopsy 把 176 个"无人认领的表项"全部命名
  （`TypeTestingStub__GrowableList@0150898`）；dae 只能证明性地命名其中 88 个分配 stub，
  另外 88 个类型测试 stub 留成裸地址。表里那 ~3.5pp 的命名差**全部**来自这里。
  正确做法是 aotopsy 那条路：对象池里的 `Type` 条目带 `type_test_stub_` 字段指向 stub，
  于是 (类型 → stub 地址) 是**可证明的**，而模式匹配不是。
- **按类目录组织、一函数一文件**（1603 个小文件）vs dae 按库组织（17 个文件）。
  这是翻阅习惯的差别，不是正确性差别——但也是 aotopsy "文件数" 看起来多的原因。

## 这次对照改动了 dae 什么

1. **覆盖率**：aotopsy 找出了 176 个 dae 没列的函数。它们是指令表的 **stub 段**——没有 Code 对象的
   表项。dae 现在把它们如实列进新的 `text/stubs.txt`（入口、字节数、能证明时给出名字），
   覆盖率因此持平；解出来的分配 stub 名字也用到了伪代码里：
   `call sub_0xfb68() /* 0xfb68 */` 变成 `call AllocationStub_UnsupportedError() /* 0xfb68 */`。
2. **一个被真值抓住的编造陷阱**：把解码扩展到类型测试 stub 看起来很容易——形状一样（先物化类 id
   再比较）——但它比较的是**裸 cid**，而分配 stub 物化的是**完整 tag 字**，
   前面那条 `mov r8d, 0x31`（49 = `_Smi`）只是 Smi 分支的初值。天真版本命名了 12 个，
   **其中 4 个是错的**（两个 `AllocateMint*Stub` 与 `AllocateContextStub` 被安上了类型测试的名字，
   还有一个成了 `_Smi`）。与 `.symtab` 对拍立刻暴露；代码退回"只命名可证明的"。
   当前状态：88/88 与真值一致，零编造。
3. **两处注释是错的，已改对**：`entry_for` 原本写"stub（idx < first_entry）返回 None"，
   暗示 `code_base_ref` 标记的是 stub 前缀；实测这些语料上 `first_entry` 是 0，
   被跳过的 167 个 Code 对象是 **`ci <= code_base_ref`** 标出的 stub 段。

## 2026-09-26 复测：真机应用，以及此前语料在哪儿骗了我们

上面那张表量的是 x64 ELF 语料。换成**真实 Flutter 应用**（用户本机 APK 集 + 一个商业 macOS 应用）
之后，结论在一个要紧的地方变了。

### 移动端（Android）Flutter 产物：**当天已修**（2026-09-26）

下面那节描述的缺口在测出来的同一天就补上了：dae 现在**随包压缩指针 profile 变体**，并按快照自带的
features 串自动选中——不需要任何额外参数：

```
dae /tmp/android/libapp.so out/          # 自动识别 dart/3.3.4 + w32-compressed 变体
```

| 应用 | SDK | dae 现在 | aotopsy（同一文件） |
|---|---|---|---|
| Reqable（安卓） | 3.3.4 | 表项 57,960、**具名函数 13,371**、库 1,734、类 3,567、**0 告警** | 57,960 函数 / 8,216 类 |
| ChatGLM | 3.11.6 | 表项 30,782、**具名函数 27,517**、库 1,211、类 4,603 | 30,782 / 5,501 |
| 学信网 | 3.7.2 | 表项 19,752、**具名函数 17,438**、库 875、类 3,256 | 19,752 / 3,819 |
| 飞书 Lark | 3.6.1 | **79 327 表项**、**具名函数 25 183**、3 194 库、6 306 类、**0 警告** | 79,327 / 12,929 |
| 微博 | 2.19.6 | **22 623 表项**、**具名函数 19 807**、750 库、3 671 类、**0 警告** | 22,623 / 4,232 |

飞书与微博都在 v0.1.4 修好，五个产物的表项数现在**全部**与 aotopsy 精确一致（飞书 79 327 表项 /
1 418 库 / 2 868 类 / 0 警告）。两者也都能端到端反编译：3 517 与 19 053 个函数块、结构化 95.9%
与 91.1%、各 1 行未映射、`dart analyze` **0 错误**（微博产出 26.3 万块 / 153 万条语句）。
剩下的诊断是 `unused_local_variable` / `dead_code` 警告，根源是调用点不显示实参（见下方 backlog），
与解析质量无关。

Reqable 的安卓产物还能反编译：**1,707 函数、95.5% 完全结构化、`dart analyze` 0 错误**，并从访问器
符号恢复出 227 个字段名——其中 144 个与 aotopsy 的类布局**名字与字节偏移完全一致、0 真冲突**
（`type` vs 它给类型参数槽的合成名 `type_arguments_field` 是命名取舍，不是分歧）。

三个应用的表项数与 aotopsy **逐一吻合**，是没有符号时能拿到的最强证据：两个独立实现算出的函数数量一致。

修法（全在 `src/engine` 与 `tools/sdk2profile.py`，不是重写）：

1. **压缩构建没有 ROData 簇** —— `NewClusterForClass` 把整个 `RODataSerializationCluster` 类包在
   `#if !defined(DART_COMPRESSED_POINTERS)` 里（内存镜像的装载地址不保证落在压缩指针可寻址的 4GB 内）。
   字符串因此走普通填充簇：alloc 逐对象写 `(length<<1)|two_byte`，fill 重写该编码 + 原始字节；
   `PcDescriptors` / `CodeSourceMap` / `CompressedStackMaps` 同理（`uvarint(len) + len 字节`）。
2. **实例字段槽按指针宽度计** —— fill 用 4 字节步长走 `next_field_offset = nfo << kCompressedWordSizeLog2`，
   字段从 8 字节头部之后开始，故槽数 = `nfo − 2`（不是 `nfo − 1`）。算错会让每个实例多读一个槽，
   填流累积漂移 4.8KB，对象池长度随即读成垃圾。
3. **VM isolate 不写字符串簇的 canonical 集合表尾** —— `StringSerializationCluster(is_canonical,
   cluster_represents_canonical_set && !vm_)`；而非压缩构建的 *rodata* 字符串簇没有这个排除。
   两条规则现在各自绑定到自己的簇形态。
4. **压缩构建的 data image 仍按 64 对齐**（指令表放在那里），表本身读到 `data_image + rodata_offset + 16`
   （它是一段 OneByteString 的载荷）。

### 缺口最初测到的样子（2026-09-26，修复前）

从 8 个 Flutter APK 里取出 `lib/arm64-v8a/libapp.so`，两个工具各跑一遍：

| 应用 | SDK（读快照自己的 hash） | aotopsy | dae |
|---|---|---|---|
| Reqable | 3.3.4 | 57,960 函数 / 8,216 类 | 漂移，已拒绝导出 |
| 飞书 Lark | 3.6.1 | 79,327 / 12,929 | 漂移，拒绝 |
| ChatGLM | 3.11.6 | 30,782 / 5,501 | 漂移，拒绝 |
| 学信网 | 3.7.2 | 19,752 / 3,819 | 漂移，拒绝 |
| 微博 | 2.19.6 | 22,623 / 4,232 | 漂移，拒绝 |
| 微信 | 2.15.0 | 未建模 | 漂移 |
| 同花顺 | 2.7.2 | 未建模 | 漂移 |

原因就写在产物自己的 features 串里（dae 本来就要扫过它才能找到头）：

```
桌面构建: product no-code_comments no-dwarf_stack_traces_mode ... macos     no-compressed-pointers
安卓构建: product no-code_comments    dwarf_stack_traces_mode ... android compressed-pointers
```

两个构建开关改变了快照布局，而 **dae 随包的 26 个 profile 全是"桌面 + 非压缩指针"**：

- `compressed-pointers`：指针宽度 4 而非 8（aotopsy 对这些产物一律报 `ptr_size: 4`），
  整个解析走过的对象布局、对齐、槽位都不同；
- `dwarf_stack_traces_mode`：Code 簇少 push 两个 ref（3.3.4 `app_snapshot.cc`：
  `if (!FLAG_precompiled_mode || !FLAG_dwarf_stack_traces_mode) { push inlined_id_to_function_;
  push code_source_map_; }`），其后的 fill 流整体错位。

两者都是 **profile 差异**（解析引擎本身没问题），所以这是一件"生成 profile 变体"的活，不是重写：
`tools/sdk2profile.py` 已经支持 `--word-size 4 --compressed`，工作区里有 24 个版本的 SDK 源码，
`dwarf_stack_traces_mode` 变体只需让 `code_refs` 的推导也认这个 flag。检测可以做到**精确**而非启发式：
dae 本来就在解析 features 串，直接按 `compressed-pointers` / `dwarf_stack_traces_mode` 选 profile 即可。

这些失败解析还暴露出两个健壮性 bug（都已修）：嵌套值渲染**无深度上限**，坏解析下数组自引用会把
导出线程的栈打穿、进程 SIGABRT（现在封顶 8 层）；解析漂移此前只打警告、照样写产物并 rc=0
（现在打 FATAL、写 `PARSE_DRIFT.txt`、以非零退出码收尾，`text/strings.txt` / `text/pp.txt`
这类原始 dump 保留——它们仍可人工读）。

版本口径值得一提：同一份 Reqable，aotopsy 报 `dart: 3.3.0`，dae 报 `3.3.4`——后者是快照自带 hash
（`ee1eb666c76a5cb7746faf39d0b97547`，与它 macOS 产物的 hash 一致，blutter 在同一文件上也这么报）
说的；aotopsy 那个是它**最近的建模版本**。

### 一个商业 macOS 应用（只有 dae 能读：aotopsy 不吃 Mach-O）

`/Applications/Reqable.app`（26 MB 的 App.framework 二进制、代码混淆、`dwarf_stack_traces_mode`）：

| | dae |
|---|---|
| 库 / 类 | 564 / 1,285 |
| 具名字段 | 2,105 |
| 反编译出的函数 | 1,808（完全结构化 1,716 = **94.9%**） |
| 未识别指令行 | 1 |
| `dart analyze` 错误 | **0** |
| `text/pp.txt` / `text/objs.txt` 与 blutter 在同一文件上的输出 | **逐字节一致** |
| 耗时 | 118 s |

aotopsy 对同一文件：`error: elfx: not an ELF file: bad magic number [202 254 186 190]`——
它的 loader 只认 ELF，所以 macOS/iOS/Windows 的 Flutter 产物是 dae 独占的地盘。
（这次 `dart analyze` 原本是 1 个错误：池里的 `"$IsolateException"` 没转义，Dart 当成字符串插值。
已修——`$` 现在与其它元字符一样转义，并补了单测。）

### 字段名正面对照（T4_blank，2.12.4）

| | dae | aotopsy |
|---|---|---|
| 具名 (类, 偏移) 对 | 34 | 149 |
| 其中合成名 | 0 | 107（泛型类的类型参数槽 `type_arguments_field`）+ 约 10 |

- **32 对名字与偏移完全一致，0 冲突**——两个独立实现读同一条快照事实
  （`MintValues[host_offset] × word_size`）的结果。
- dae 有 2 个名字是 aotopsy 的布局表里没有的（走访问器符号那条路来的）。
- aotopsy 在**呈现**上仍领先：它用全程序类型推断把访问重写成 `base.field`；
  dae 把名字写成归属注释，保留 `mem(base, disp)`。

## 说明与保留

- **aotopsy 只吃 ELF**（`libapp.so`，"ELF parse"）。Flutter macOS/iOS 的 `App.framework`（Mach-O）
  喂不进去，所以本文档里没有 arm64 的对照；dae 的 arm64 数据在 [`DECOMPILER.zh.md`](DECOMPILER.zh.md)。
- 要做规范的 arm64 对照需要 **Android 的 `libapp.so`**（`flutter build apk --release`）：
  需要 Android SDK/NDK 且能连 Maven，本机两者都不具备。
- aotopsy 的**额外能力**（行为分类、加解密/网络关键词、Frida 导出、SARIF、dispatch-table 恢复、
  evidence/confidence 记录）没有参与对照：那些是 dae 不做的事，而不是共有能力上的差异。