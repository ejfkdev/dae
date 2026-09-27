# dae

[English](README.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/ejfkdev/dae)](https://github.com/ejfkdev/dae/releases/latest)
[![crates.io](https://img.shields.io/crates/v/dae-rs)](https://crates.io/crates/dae-rs)
[![Release CI](https://img.shields.io/github/actions/workflow/status/ejfkdev/dae/release.yml?label=build)](https://github.com/ejfkdev/dae/actions/workflows/release.yml)
[![Publish CI](https://img.shields.io/github/actions/workflow/status/ejfkdev/dae/publish.yml?label=publish)](https://github.com/ejfkdev/dae/actions/workflows/publish.yml)
[![Built with ZCode](https://img.shields.io/badge/Built%20with%20ZCode-000000.svg?style=flat&logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMTE4IiBoZWlnaHQ9IjEwMCIgdmlld0JveD0iMCAwIDI1NiAyMTgiPjxwYXRoIGZpbGw9IiNmZmZmZmYiIGQ9Ik0xMzQuNCAwLjEzMDE1MkwxMTEuNDggMjUuNjAyMkMxMTEuNjY1IDI5LjU2OTkgMTA5LjA1NCAzMi4wMDE5IDEwNC4wNjQgMzIuMDAxOUg2LjM5OTlWMEM2LjM5OTkgMC4xMzAxNDkgMTM0LjQgMC4xMzAxNTIgMTM0LjQgMC4xMzAxNTJaIi8+PHBhdGggZmlsbD0iI2ZmZmZmZiIgZD0iTTI1NiAwLjEzMDEyN0wxMDIuNDAxIDIxNy43MzJIMDBMMTUzLjU5OSAwLjEzMDEyN0gyNTZaIi8+PHBhdGggZmlsbD0iI2ZmZmZmZiIgZD0iTTEyMS42MDEgMjE3LjczMkwxMzkuNjUgMTkyLjEzNEMxNDIuNDY1IDE4OC4xNjYgMTQ3LjA3NiAxODUuNzM0IDE1Mi4wNjcgMTg1LjczNEgyNDkuNjA0VjIxNy43MzZIMTIxLjYwMVYyMTcuNzMyWiIvPjwvc3ZnPg==)](https://zcode.z.ai/)

> 配置驱动的 **Dart AOT 快照**分析与调试信息导出工具。零依赖 Dart SDK、不运行目标程序：从 Mach-O / ELF / PE 中定位内嵌快照，导出与 [blutter](https://github.com/worawit/blutter) 一致的符号与结构供 IDA / radare2 / Frida 使用（对移植来源的参考实现有四处有意修正，见 `src/export/mod.rs`），并**把函数反编译成 `dart analyze` 认可的 Dart**。覆盖桌面**与**真机移动端（压缩指针）产物。

适用于任意 Dart AOT 产物——Flutter release 构建、`dart compile exe`、`dart compile aot-snapshot`（Dart 2.7+ cluster 快照）。

## 特性

- **开箱即用、自动识别**——26 份 SDK profile + **21 份压缩指针变体**内嵌进二进制；按快照哈希匹配版本，变体（`compressed-pointers`，即所有移动端 Flutter 构建）按快照自带的 features 串自动选中，自定义/Flutter 引擎构建走结构探针兜底。验证用的是**真实上线应用**，不只是我们自己编的样本：

  - **Android arm64**——Reqable 3.3.4、飞书 3.6.1、ChatGLM 3.11.6、学信网 3.7.2、微博 2.19.6。
    五个产物的指令表表项数与 aotopsy **完全一致**（57 960 / 79 327 / 30 782 / 19 752 / 22 623），
    全部 0 警告；飞书与微博还能端到端反编译成 `dart analyze` **0 错误**的 Dart
    （结构化 95.9% 与 91.1%）。
  - **macOS arm64**——Reqable.app 3.3.4：70 996 表项、0 警告、1 808 个函数结构化 94.9%、
    `dart analyze` **0 错误**。
  - **本地构建的 flutter-samples demo**（Dart 3.13.0）——`material_3_demo`（5 107 行）与
    `animations`（2 108 行）：15 796 与 11 102 个函数，结构化都是 92.5%，`dart analyze` 都 **0 错误**。
    因为源码已知，这两个是**对着源码判**的：`lib/` 里声明的公开 class/mixin/enum 分别恢复出
    98.8% 与 100%，源码字符串字面量分别有 95.4% 与 97.4% 出现在产物里，源文件到恢复出的库
    分别映射 18/18 与 21/23。`tests/app_truth.rs` 会断言这些比率（下限 0.90），
    链路一旦悄悄退化就会失败。
- **反编译产出合法 Dart**——lift → CFG → 结构化发射，不是反汇编转储：循环、`if/else`、
  `break`/`continue`、对象池字面量在其载入处内联、恢复出的字段名以归属注释形式标注。
  26 份语料（291 个文件、24 253 个函数）的产物 **`dart analyze` 错误为 0**；真机应用同样站得住——
  飞书 3.6.1 结构化 95.9%、微博 2.19.6 结构化 91.1%（19 053 个函数、153 万条语句），两者均 0 错误。
  不可归约的控制流保留显式 `gotoLabel` 并在函数头打 `NOTE`，绝不静默压平。
  见[反编译器](#反编译器实验性)。
- **快**——以下都是本版二进制实测：9 MB 的 macOS Flutter 样本导出 0.26 s；`--decompile` 在
  飞书（25.6 MB 安卓、25 183 个函数）1.6 s、`material_3_demo`（14 MB macOS、15 796 个函数）2.4 s、
  微博（9 MB 安卓、19 053 个反编译函数 / 153 万条语句）3.5 s，峰值 RSS 179–211 MB。
  同一产物上比 v0.1.7 **快约 50 倍**（106.8 s → 1.91 s）——收益来自「不再每函数重建全局不变数据」，
  不是换了更快的算法。
- **双语 CLI**——中文语系输出中文，其余英文；`DAE_LANG=zh|en` 可强制指定。
- **渐进式模式**——20 条子命令像查数据库一样查快照（`libs`/`classes`/`functions`/`members`/
  `strings`/`findrefs`/`callers`/`callees`/`pp`/`objs`/`stubs`……），再只反编译你要的那一份
  （`getclass`/`getmethod`/`getlib`/`decompile --app`）。查询在小语料上 15–30 毫秒、
  在 15 796 函数的应用上 43–311 毫秒；那个应用全量导出 0.54 秒，加 `--decompile` 约 2.1 秒、
  上千个文件。每条命令的输出都能直接抄进下一条。
  见[渐进式](#渐进式先查清单再定点反编译)。
- **不需要工具链**——单个自足二进制：无需 Dart SDK、无需装 Flutter，且**从不运行目标程序**，
  只解析它。Mach-O/ELF/PE 解析与全部 47 份 profile 都内嵌在二进制里。

## 安装

| 方式 | 命令 |
|---|---|
| Homebrew（macOS） | `brew install ejfkdev/tap/dae` |
| cargo | `cargo install dae-rs` |
| 预编译 | 从 [Releases](https://github.com/ejfkdev/dae/releases/latest) 下载——Windows/macOS/Linux × x64/arm64 |
| 源码 | `cargo build --release` |

macOS 预编译二进制是 ad-hoc 签名；首次被 Gatekeeper 拦截时执行：`xattr -dr com.apple.quarantine dae`。

*（crates.io 包名是 `dae-rs`，因为 `dae` 已被占用；仓库、库与二进制均名为 `dae`。）*

## 用法

```bash
dae <binary> <out_dir>                       # 自动识别 Dart 版本
dae export <binary> <out_dir>                # 同上，显式动词
dae <binary> <out_dir> --sdk-profile P.json  # 或强制指定
dae <binary> <out_dir> --app --decompile     # 只要应用侧代码（排除 dart: 与 package:flutter）

dae help                                     # 全部子命令（分组）
dae help findrefs                            # 单条命令的选项与输出列
dae decompile <binary> | less                # 整个应用的伪代码走 stdout
```

```console
$ dart compile exe demo.dart -o demo
$ dae demo out
SDK profile: dart/3.13.0 (version-hash match)
export done -> /绝对路径/to/out:
  ida_script/  r2_script/  frida.js  asm/
  text/  pp.txt · objs.txt · strings.txt · libs.txt · classes.txt · functions.txt · arrays.txt · maps.txt · fields.txt
```

- **IDA**——`File → Script file…` 选择 `ida_script/addNames.py`。函数名、边界与 `DartThread`/`DartObjectPool` 结构落入数据库（装载基址自动重定）。
- **radare2**——`r2 -i r2_script/addNames.r2 <binary>`，会话内执行 `to r2_dart_struct.h`。
- **Frida**——改好标记的 hook 行后 `frida -f <app> -l out/frida.js`。

## 产物

| 输出 | 用途 |
|---|---|
| `ida_script/addNames.py` | IDAPython：命名 + 边界 + 结构 |
| `r2_script/addNames.r2` | radare2 flag/注释（库 → 类 → 方法） |
| `*_dart_struct.h` | Dart 运行时结构（`r2_script/r2_dart_struct.h`、`ida_script/ida_dart_struct.h`） |
| `frida.js` | Frida 模板 + 运行时 `Classes` 数组 |
| `asm/*.dart` | 反汇编 + blutter 风格 IL 注释（arm64） |
| `pp.txt` | 对象池条目（在 `text/` 下） |
| `objs.txt` | 用户类实例递归 dump（在 `text/` 下） |
| `strings.txt` | 完整字符串表（在 `text/` 下） |
| `libs.txt` | 库清单（URI + 库名，在 `text/` 下） |
| `classes.txt` | 类清单（ref、cid、库、类名；在 `text/` 下） |
| `functions.txt` | 平铺 `库.类.方法 → 偏移` 索引（在 `text/` 下） |
| `arrays.txt` / `maps.txt` | 每个 List / Map 对象及其内容（在 `text/` 下） |
| `text/fields.txt` | 恢复出的具名字段：来源（快照 Field 簇 `rec` / 隐式访问器名 `accessor`）+ 字节偏移 |
| `text/stubs.txt` | 指令表里**没有** Code 对象的条目（`functions.txt` 略掉的 stub 前缀）；只在能从分配 stub 序言证明时给名字，否则留空 |
| `text/call_edges.txt` | 调用边：直接 `bl`/`call` 目标 + 间接调用点；每类分配 stub 由序言解出名字 |
| `callgraph.dot` | 已命名函数之间的直接调用图（Graphviz DOT） |
| `dart/*.dart` | 每函数伪代码，**可过 `dart analyze`**；**一个库一个文件**，由 `--decompile` 或 `decompile` 子命令产出 |

结构头按目标生成：`DartThread` 取自「版本 × 架构」布局表，`DartObjectPool` 由目标自身对象池生成。

## Dart 版本支持

| 范围 | 状态 |
|---|---|
| 3.0.0 – 3.14β | ✅ 已验证——完整用户函数 |
| 2.15.0 – 2.17.0 | ✅ 已验证——完整用户函数 |
| 2.10.4 – 2.14.4 | 函数名 + 地址 |
| 2.7.2 | 仅对象层 |
| 1.24.3 / 2.0.0 | ❌ JIT 快照（非 AOT） |

## 工具兼容性

| 工具 | 状态 |
|---|---|
| IDA 9.3 / 9.4 | ✅ 端到端实测（命名 + 结构） |
| IDA 7.x – 8.x | 预期可用——7.x 起同套 typed API |
| radare2 6.2 | ✅ 实测——脚本零错误 |
| radare2 5.x | 预期可用——仅用长期稳定命令 |
| rizin | 可解析/执行；单地址单 flag 会跳过同地址附加 flag |
| Frida 14 – 17 | 核心 `Interceptor`/`Module`/`ptr` API |

## 工作原理

三层结构；引擎跨版本不变，仅增配置：

| 层 | 路径 | 内容 |
|---|---|---|
| 引擎 | `src/` | varint/cluster 遍历、fill 解释器、命名去混淆、各导出器 |
| SDK profile | `profiles/sdk/*.json` | cid 枚举、字段布局（fill DSL）、tagging、偏移 |
| 平台 profile | `profiles/platform/*.json` | 容器解析、符号名、寄存器角色 |

规范见 [`docs/PROFILES.zh.md`](docs/PROFILES.zh.md) · 反编译基线见 [`docs/DECOMPILER.zh.md`](docs/DECOMPILER.zh.md) · 与 aotopsy 的实测对照见 [`docs/COMPARISON.zh.md`](docs/COMPARISON.zh.md)。

## 渐进式（先查清单，再定点反编译）

全量导出会写出上千个文件，但多数时候你只要一个类、一个包，或者只是想知道「这个字符串被谁用了」。
先查、再定点反编译（`dae help` 有全部命令，`dae help <cmd>` 有单条命令的选项与输出列）：

```
先摸清全貌
  dae info      <binary>                        快照 / SDK / 规模——不写任何产物
  dae libs      <binary> [pattern]              库（包）清单 + 类数/函数数
  dae classes   <binary> [pattern] [--lib P]    类清单
  dae functions <binary> [pattern] [--lib P]    函数清单（入口 / 字节数 / 归属）
  dae largest   <binary> [-n N]                 按代码字节数排前 N

找东西
  dae strings   <binary> [-f TEXT]              快照字符串表检索
  dae fields    <binary> [pattern]              具名字段（来源 + 字节偏移）
  dae members   <binary> [NAME] [--class X]     方法与字段的统一名字检索
  dae findrefs  <binary> string TEXT            哪些代码位置加载了这个字面量
  dae findrefs  <binary> kind NAME              ……或加载了这个种类的对象
  dae callers   <binary> <NAME|0xADDR>          谁调用了它（静态直接调用边）
  dae callees   <binary> <NAME|0xADDR>          它调用了谁（列与 callers 相同）

对象层（与 text/ 里的同名产物同源）
  dae pp        <binary> [pattern]              对象池条目
  dae objs      <binary> [pattern]              用户类实例（含字段值）
  dae stubs     <binary> [pattern]              指令表里没有 Code 对象的条目

反编译
  dae getclass  <binary> <CLASS>                只反编译这个类
  dae getmethod <binary> <CLASS.method>         只反编译这个方法
  dae getlib    <binary> <LIB>                  只反编译这个库（包）
  dae decompile <binary> [-o DIR|FILE.dart|-]   全部，或你收窄后的全部

低层
  dae disasm    <binary> <CLASS[.method]>       原始反汇编（arm64 保留 IL 注释）

全量导出
  dae export    <binary> <out_dir> [--decompile]
  dae           <binary> <out_dir> [--decompile]   快捷形，与上面完全等价
```

几条为了「能组合」而定的口径：

- **stdout 是数据通道**：查询结果与反编译伪代码走 stdout，不掺统计与耗时；目标、SDK profile、
  告警、计数一律走 stderr。于是 `dae getclass app Foo | less`、`dae classes app > index.tsv`
  都能直接用。`-o FILE` 改为落盘；`-o FILE.dart` 合并成单文件，`-o DIR` 写成与全量导出同形的
  `<DIR>/dart/<库>.dart`。**唯一的例外是全量导出**，而且是有意的：它的摘要走 stdout，
  因为那才是它的人读通道。
- **名字要能抄回来**：库名三种写法等价——`functions.txt` 的 lib 列（`testing_app$screens$home`）、
  `libs.txt` 的 URL（`package:testing_app/screens/home.dart`）、产物文件名
  （`testing_app_screens_home`）；且库名按**前缀**匹配，`getlib testing_app` 就是整个包。
  类名默认精确（大小写不敏感兜底），`--fuzzy` 才子串。函数名收 `Class.method`、裸方法名、
  产物里的下划线形式 `Class_method`，**以及** `callers`/`callees`/`findrefs`/`call_edges.txt`
  输出的全点号形式 `lib.Class.method`——所以上一条命令的输出能直接喂进下一条，不用改写。
- 没命中会给可操作的提示：`getclass HomePag` 列几个真名字；`findrefs kind NoSuchKind`
  列出这个池里真实存在过的对象种类。
- **范围收窄**：`--lib/--class/--func` 作用于函数维度的产物（`functions.txt`、`asm/`、`dart/`、
  `call_edges.txt`、`callgraph.dot`）；对象层 dump（`pp`/`objs`/`strings`/`libs`/`classes`/
  `arrays`/`maps`）保持完整——它们是你挑选时的索引。另有三个**整库排除**：
  `--exclude-lib PATTERN`（可重复）、`--no-sdk`（URL 以 `dart:` 开头的库）、`--app`
  （再排除 `package:flutter`）。后两个按库的**原始 URL** 判，不按 mangled 名猜——
  `dart:core` 会被 mangle 成 `dart_core`，而一个叫 `dart_core_extra` 的包长得几乎一样。
  实测真实 Flutter 应用：505 库 / 15 796 函数 → `--no-sdk` 489 / 11 016 → `--app` 56 / 765。
- **退出码**：`0` 成功；`1` 运行期错误（含没命中、解析漂移）；`2` 用法错误。
- **不提供的，以及为什么**：`findrefs` 没有 `field` 这个 kind——编译后的机器码里没有符号化的
  字段引用，只剩裸位移，按位移匹配会把大量无关的 `[x, #0x18]` 报成命中，那是猜不是查。
  没有 `hierarchy`——dae 能读到的父类链没有真值支撑（拿应用自己的源码对照，
  `App extends StatefulWidget` 被解成 `SceneBuilder`），而错的继承链比没有更糟。
  同一条没解对的链还喂给 `frida.js` 的 `sid` 字段与 `text/objs.txt` 里的祖先分组，
  所以那两处也请当作不可信；源码里已在对应位置标注。也没有 ddc 那种从 manifest 取应用包名的
  `--app`——Dart 快照没有 manifest，猜包名就是编造。

### 为什么 dart/ 是一个库一个文件，而不是一个类一个文件

因为 Dart 源码就是这么组织的：一个 *library* 通常就是一个 `.dart` 文件、里面放很多类，
而 Dart 的私有性是**库级**的，不是类级。`_SliderState` 之所以对 `Slider` 可见，正因为它们
同属一个库——反编译产物里 `Slider_createState()` 调的就是 `SliderState_ctor()`
（对应 Flutter 的 `createState() => _SliderState()`）。按库分文件忠实镜像了原始布局，
所以这些引用仍是**真定义**。

按类拆也能过 `dart analyze`（每文件的前导会声明「本文件用到但没定义」的标识符，跨类调用于是
退化成 `dynamic` 调用），但代价是保真度——本来能读到的定义变成不透明的桩；文件数约涨 8 倍
（同一份样本 4 150 个类 vs 535 个库）；还会撞名，因为 `_SliderState` 去掉下划线后可能与
公开的 `SliderState` 冲突。想要以类名命名的文件，`dae getclass App HomePage -o HomePage.dart`
现在就能给；而 `-o DIR` 刻意保持与全量导出同形，好让「选出来的是全量的子集」这条能字面校验。

实测成本：一个 15 796 函数的 Flutter 应用，全量 `--decompile` 约 2.1 秒、写约 1000 个文件；
小语料上各查询 15–30 毫秒；同一个大应用上 `findrefs` 0.21 秒、`callees` 0.30 秒、
`decompile --app` 0.20 秒。快照解析本身约 50 毫秒——渐进式省下的是写盘。

## 反编译器（实验性）

`dae --decompile` 额外产出 `dart/<库>.dart`：每个已命名函数一段伪代码，流程与同类工具
一致（机器相关 lift → 基本块 → 发射）。

**目前做到的**：

- 由 `cmp`/`fcmp`/`test` + 跳转折出的真条件（`if (rdx < 2)`）
- 框架寄存器名（`PP`/`THR`/`SP`/`FP`，以及各平台 profile 的 `register_aliases`），内存操作数内部也替换
- 直接调用目标带名字（`call router`）；没有名字的入口写成 `sub_0x...`
- **还原对象池常量**：`ldr x0, [PP, #0x17f8]` 写成 `x0 = "Hello" /* pp+0x17f8 */`
  （字符串字面量与立即数；非字符串条目给类型注释）。arm64 与 x64 都做过源码对照
- **字段名：只写可证的**。AOT 会删掉几乎全部字段名（`Precompiler::DropFields`），dae 只走两条路
  ——快照里幸存的 `Field` 对象（名字 + 由 Mint 簇取回的字索引）、以及隐式 getter/setter 名
  （函数体只碰一个字段）。名字以**归属注释**出现，且不声称基址的类型：
  `x0 = mem((local_0), 0x17); /* _FutureListener.result (off 0x18) */`。覆盖：arm64 样本 60 个名字
  / 218 处注解，Flutter 应用 367 / 438；两条路对 41 条中的 40 条独立得到同一结论，全语料 0 冲突。
  `dae fields` 列这张表，导出产物落在 `text/fields.txt`
- 栈槽渲染成局部变量（`local_8`）；帧保存/恢复与屏障保留为 `// frame:` / `// barrier:` 注释
- 每个函数上方保留原始反汇编注释块（便于核对）

**产物是合法 Dart**：能解析，能过 `dart analyze` 且零错误——机器写法被改写成
`mem(base, disp)`/`memSet(...)`/`callIndirect(x8)`/`gotoLabel(0x..)`，名字收敛成合法标识符
（mixin application 的类名里带 `&`，而 `&` 在 Dart 里是运算符），每个文件顶部还有一段
*伪运行时*前导，声明机器层概念以及正文用到的寄存器与跨库调用目标。这段声明不是"假装编译得过"，
它把「机器层到哪里为止、Dart 语义从哪里开始」显式写了出来。
基线：真实 Flutter 应用（412 文件 / 10 245 函数）**680 515 → 0** 个错误，27 个语料全部 0；
表、修复过程与逐样本分数见 [`docs/DECOMPILER.zh.md`](docs/DECOMPILER.zh.md)。

**控制流已结构化**：支配树找出自然循环（回边 = 头支配尾），再按区域递归发射——两分支汇合的
写成 `if/else`（汇合点正好是区域终点也算合法菱形），一支返回的写成 `if (c) { return ... }`，
循环头写成 `while`，跳出循环的分支写成 `break`/`continue`。门禁语料上 87–92% 的函数完全结构化；
其余保留 `gotoLabel` 并在函数头打 `NOTE` 标记。

**还没做的**：跨基本块的表达式合成（目前是块内若干层）、**基址类型**的恢复（池值与字段名都有了，
但基址寄存器属于哪个类没跟踪，所以访问写成 `mem(base, disp) /* 类.字段 */` 而不是 `base.field`；
补法与 aotopsy 的 `typetrack` 同源）。认不出的指令原样输出为 `// unmapped:`，不做近似；
运行摘要里会打印这个行数——可以把它当质量刻度看。

每次改动都有门禁：`tests/app_truth.rs`（反编译本地构建的 **flutter-samples** 应用，并**对其真实源码判**——
恢复出的公开类型、字符串字面量、库映射，下限 0.90；用 `DAE_DEMO_ROOT` 指向检出目录）、
`tests/source_truth.rs`（用本机 `dart` 现编 `tests/fixtures/truth.dart`，
反编译后**对源码判**；`DAE_TRUTH_ANDROID=1` 时再对压缩指针 arm64 产物跑同一套）、
`tests/dart_valid.rs`（真跑 `dart analyze`，要求零错误）、
`tests/decompiler_shape.rs`（产物文件花括号必须配平（不配平=静默丢分支）、函数体内语句必须正常
结束、结构化率有下限、**地址必须自洽**（至少 80% 的函数入口要像序言、直接调用要命中函数入口））与
`tests/field_names.rs`（两条字段名路径必须互相印证、零冲突，且产物里每个注解都要在恢复表里
找得到——这就是零编造判据）。
最后这条是本项目吃过亏补上的：Mach-O appended 快照的指令段定位曾经缺失，反编译器读的是
**别的代码**，而所有基于名字的指标却全是绿的。它的判据是**序言率**，不是「末指令是终止符」——
后者本身就是个假门禁：它在数 x64 的 `int3` 填充，地址全错时照样打出 95.7%。
定位错位时序言率 51–58%，正确时 91–100%。

两个 `dart analyze` 门禁还会**校验自己的解析**：拿工具的退出码反查错误数（0/1/2 ⇒ 无错误、
3 ⇒ 至少一个），并要求总结行必须出现。因为 `dart analyze` 指向不存在的目录时返回 rc=64 +
usage 文本，里面一条 `error - ` 都没有，朴素解析器会读成「0 错误」然后放行。两个门禁各带一条
`*_rejects_directory_it_never_analyzed` 自检测试，那个洞一回来就失败；`dart_valid` 还断言每个
语料都真的产出了文件与函数，于是「产物为空」不能冒充「产物干净」。

另有两个门禁确实存在，但是**维护者本地的：既不在本仓库里，也不进 CI**。`scripts/` 与 `tools/`
连同它们要吃的语料（`testing/`、`dart/dart_samples/`、`dart/dart_profiles/`——大体积二进制与
SDK 检出）一起被 gitignore，所以下面这些路径**在新克隆的仓库里不存在**。列出来只是让发版背后的
验证过程可见：

- `scripts/regress_all.sh` —— 25 版本矩阵；对象层必须与存档参考输出逐字节一致。
- `scripts/check_profiles.sh` —— profile 新鲜度；用 `tools/sdk2profile.py` 从 SDK 源码重新生成
  全部 47 份落盘 profile（26 份 w64 + 21 份压缩指针变体）并对拍，孤儿变体或变体数不符预期
  同样失败。它**故意**把应有时数写死：「文件不在就跳过」正是上面 `dart analyze` 门禁刚堵掉的
  那类假通过形态。

**新克隆到底验证了什么。** 能跑的东西确实全在 `tests/` 里，但 6 个门禁文件中有 5 个要吃上面那些
被 gitignore 的语料，缺了就**自行跳过**，而 `cargo test` 默认把跳过提示吞掉——于是一份干净检出
会报告「套件全绿」，实际上几乎什么都没量。只有 `tests/source_truth.rs` 是自足的：它自己编
`tests/fixtures/truth.dart`，除了 `PATH` 上有 `dart` 之外什么都不需要。为此，所有「因缺依赖而
跳过」的分支都统一走一个 helper，并且

```bash
DAE_REQUIRE_GATES=1 cargo test --release
```

会把这类跳过变成**硬失败**。维护者在有语料的检出里跑它；这是区分「门禁通过了」与「门禁根本没跑」
的唯一办法。显式 opt-in 的跳过（安卓源码真值链需要 `DAE_TRUTH_ANDROID=1`）不受影响。

## 已知限制

- `text/pp.txt` 首行报的是 `pool heap offset: unavailable`。blutter 这个值是算出来的
  （`pool 地址 - heap_base`），需要加载后的 image 布局；dae 解析的是快照流，两样都没有，
  于是如实说明而不是印个数字。（它曾经印硬编码的 `0x10f000080`，那是从 Python 参考实现
  继承来的——对 macOS 与安卓、压缩与非压缩指针都印同一个值。
  `tests/cli.rs::pp_header_is_not_fabricated` 防止它回来。）对象池**条目**不受影响：
  `pp.txt` 照旧解析全部条目。
- **范围外：非标准产物与占位文件。** 本地 41 个 APK 里恰好 8 个带 `lib/arm64-v8a/libapp.so`，
  其中三个**不是标准 Flutter AOT 快照**，dae 会明确说明而不是猜：微信的 `libapp.so` 在 APK 内部
  **本身就是 21 字节的 `CSOS` 占位**（不是我提取错，真载荷在别处）；钉钉的 features 串带
  `enable_aion` + `llvm_compiler`，即厂商分支把 AOT 编译器换成了 LLVM 后端，其快照版本哈希
  对不上任何已知 SDK，只能退到低置信度的结构探针。同花顺是**真正的 Dart 2.7.2** 产物，
  表现与参考样本 `hello_2.7.2` **完全一致**：字符串与对象层能导出，但指令表既不在快照头里、
  也无法从 Code 簇的 text-offset 累加得到，因此没有函数地址。这是 ≤2.9 的已知上限，
  不是该产物特有的失败。
- **Dart 2.18.1 不可用。** 它的 fill 布局还有第二处**尚未定位**的错误：按源码判定的正确
  `Function` 形状（2.19.6 样本与真机 2.19.6 产物双重印证）解析会塌陷成 `libraries=1 / classes=1`。
  旧布局在 `hello_2.18.1.aot` 上分数更好，只是因为多读的那个 varint 在**补偿**另一处错——它同样
  只解出 `classes=2`（健康值约 320）。该样本已连同原因登记进 `tests/ground_truth.rs` 的
  `KNOWN_COLLAPSED`，而 `FUNC_FLOOR` 会让任何**新**的塌陷直接失败。在找到第二处错误之前，
  2.18.1 应视为不支持；2.15/2.16/2.17 与 2.19+ 正常。
- 地址是文件偏移空间，非运行时 VA（与 blutter 参考实现一致）
- 快照/指令段定位分三层：符号表（`kDartVm*` / 单快照的 `kDartSnapshot*`）→ Mach-O 的
  `LC_NOTE __dart_app_snap` 内嵌 blob（`dart compile exe` 与部分 Flutter 产物）→ 被分析切片内
  的魔数扫描。只落到最后一层时指令段地址不可得，dae 会明确提示，此时依赖地址的产物只到对象层
- `asm/` 的 IL 注释仅 arm64（x64 仅反汇编）
- 调用图：间接调用（`blr` / `call reg`）目标运行时才算得出，按设计如实留空；直接目标
  落在已命名函数或「每类分配 stub」（从 stub 序言解出类 id）上时给出名字，其余只写地址；
  2.16.x 的类表层尚未解析，该版本整体跳过 stub 命名（以覆盖率体现，绝不编名）
- 剥离 COFF 符号表的 PE 需先从 `.pdb` 回填符号
- Dart 1.24 / 2.0 是 JIT 快照，不支持

## 许可证

[MIT](LICENSE)