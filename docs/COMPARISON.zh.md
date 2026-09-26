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
  `tests/ground_truth.rs` 是 90.6%，aotopsy 的 README 是 90.2%）——统一规则下都更低，这是预期内的。
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

## 说明与保留

- **aotopsy 只吃 ELF**（`libapp.so`，"ELF parse"）。Flutter macOS/iOS 的 `App.framework`（Mach-O）
  喂不进去，所以本文档里没有 arm64 的对照；dae 的 arm64 数据在 [`DECOMPILER.zh.md`](DECOMPILER.zh.md)。
- 要做规范的 arm64 对照需要 **Android 的 `libapp.so`**（`flutter build apk --release`）：
  需要 Android SDK/NDK 且能连 Maven，本机两者都不具备。
- aotopsy 的**额外能力**（行为分类、加解密/网络关键词、Frida 导出、SARIF、dispatch-table 恢复、
  evidence/confidence 记录）没有参与对照：那些是 dae 不做的事，而不是共有能力上的差异。