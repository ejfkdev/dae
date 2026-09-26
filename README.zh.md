# dae

[English](README.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/ejfkdev/dae)](https://github.com/ejfkdev/dae/releases/latest)
[![crates.io](https://img.shields.io/crates/v/dae-rs)](https://crates.io/crates/dae-rs)
[![Release CI](https://img.shields.io/github/actions/workflow/status/ejfkdev/dae/release.yml?label=build)](https://github.com/ejfkdev/dae/actions/workflows/release.yml)
[![Publish CI](https://img.shields.io/github/actions/workflow/status/ejfkdev/dae/publish.yml?label=publish)](https://github.com/ejfkdev/dae/actions/workflows/publish.yml)
[![Built with ZCode](https://img.shields.io/badge/Built%20with%20ZCode-000000.svg?style=flat&logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMTE4IiBoZWlnaHQ9IjEwMCIgdmlld0JveD0iMCAwIDI1NiAyMTgiPjxwYXRoIGZpbGw9IiNmZmZmZmYiIGQ9Ik0xMzQuNCAwLjEzMDE1MkwxMTEuNDggMjUuNjAyMkMxMTEuNjY1IDI5LjU2OTkgMTA5LjA1NCAzMi4wMDE5IDEwNC4wNjQgMzIuMDAxOUg2LjM5OTlWMEM2LjM5OTkgMC4xMzAxNDkgMTM0LjQgMC4xMzAxNTIgMTM0LjQgMC4xMzAxNTJaIi8+PHBhdGggZmlsbD0iI2ZmZmZmZiIgZD0iTTI1NiAwLjEzMDEyN0wxMDIuNDAxIDIxNy43MzJIMDBMMTUzLjU5OSAwLjEzMDEyN0gyNTZaIi8+PHBhdGggZmlsbD0iI2ZmZmZmZiIgZD0iTTEyMS42MDEgMjE3LjczMkwxMzkuNjUgMTkyLjEzNEMxNDIuNDY1IDE4OC4xNjYgMTQ3LjA3NiAxODUuNzM0IDE1Mi4wNjcgMTg1LjczNEgyNDkuNjA0VjIxNy43MzZIMTIxLjYwMVYyMTcuNzMyWiIvPjwvc3ZnPg==)](https://zcode.z.ai/)

> 配置驱动的 **Dart AOT 快照**调试信息导出工具。零依赖 Dart SDK、不运行目标程序：从 Mach-O / ELF / PE 中定位内嵌快照，导出与 [blutter](https://github.com/worawit/blutter) 一致的符号与结构。

适用于任意 Dart AOT 产物——Flutter release 构建、`dart compile exe`、`dart compile aot-snapshot`（Dart 2.7+ cluster 快照）。

## 特性

- **开箱即用、自动识别**——26 份 SDK profile 内嵌进二进制；按快照哈希匹配版本，自定义/Flutter 引擎构建走结构探针兜底。
- **快**——24 MB 的 Flutter 样本约 0.07 s 导出（≈Python 参考实现的 27 倍）。
- **双语 CLI**——中文语系输出中文，其余英文；`DAE_LANG=zh|en` 可强制指定。
- **渐进式模式**——`dae libs`/`classes`/`functions`/`strings`/`callers` 像查数据库一样查快照，
  再用 `dae getclass`/`getmethod`/`getlib` 只反编译那一份（`dae info` 0.03 秒 vs 全量 1.9 秒），
  见[渐进式](#渐进式先查清单再定点反编译)。
- **零依赖**——直接解析 Mach-O/ELF/PE，无需 Dart SDK 或 Flutter 工具链。

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
dae <binary> <out_dir> --sdk-profile P.json  # 或强制指定
dae help                                     # 渐进式子命令（先查清单，再定点反编译）
```

```console
$ dart compile exe demo.dart -o demo
$ dae demo out
SDK profile: dart/3.13.0 (version-hash match)
export done -> /绝对路径/to/out:
  ida_script/  r2_script/  frida.js  asm/
  text/  pp.txt · objs.txt · strings.txt · libs.txt · classes.txt · functions.txt · arrays.txt · maps.txt
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
| `text/call_edges.txt` | 调用边：直接 `bl`/`call` 目标 + 间接调用点；每类分配 stub 由序言解出名字 |
| `callgraph.dot` | 已命名函数之间的直接调用图（Graphviz DOT） |
| `dart/*.dart` | 每函数伪代码，**可过 `dart analyze`**（加 `--decompile`） |

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

全量导出会写出上千个文件，但多数时候你只要一个类或一个包。先查、再定点反编译
（`dae help` 有全部选项）：

```
dae info      <binary>                        快照 / SDK / 规模——不写任何产物
dae libs      <binary> [pattern]              库（包）清单 + 类数/函数数
dae classes   <binary> [pattern] [--lib P]    类清单
dae functions <binary> [pattern] [--lib P]    函数清单（入口 / 字节数 / 归属）
dae strings   <binary> [-f TEXT]              快照字符串表检索
dae largest   <binary> [-n N]                 按代码字节数排前 N
dae callers   <binary> <NAME|0xADDR>          谁调用了它（静态直接调用边）
dae disasm    <binary> <CLASS[.method]>       原始反汇编（arm64 保留 IL 注释）
dae getclass  <binary> <CLASS>                只反编译这个类
dae getmethod <binary> <CLASS.method>         只反编译这个方法
dae getlib    <binary> <LIB>                  只反编译这个库（包）
```

几条为了「能组合」而定的口径：

- **stdout 是数据通道**：查询结果与 `get*` 的伪代码走 stdout，不掺统计与耗时；目标、
  SDK profile、告警、计数一律走 stderr。于是 `dae getclass app Foo | less`、
  `dae classes app > index.tsv` 都能直接用。`-o FILE` 改为落盘；`get*` 的 `-o FILE.dart`
  合并成单文件，`-o DIR` 则写成与全量导出同形的 `<DIR>/dart/<库>.dart`。
- **名字要能猜中**：库名三种写法等价——`functions.txt` 的 lib 列（`testing_app$screens$home`）、
  `libs.txt` 的 URL（`package:testing_app/screens/home.dart`）、产物文件名（`testing_app_screens_home`）；
  且库名按**前缀**匹配，`getlib testing_app` 就是整个包。类名默认精确（大小写不敏感兜底），
  `--fuzzy` 才子串。函数名收 `Class.method`、裸方法名，以及你刚从产物里抄出来的
  `Class_method` 下划线形式。
- 没命中会给提示：`getclass HomePag` 会列几个真名字，而不是静默什么都不做。
- `--lib/--class/--func` 也能加在全量导出上，得到**筛选导出**：函数维度的产物
  （`functions.txt`、`asm/`、`dart/`、`call_edges.txt`、`callgraph.dot`）缩到选中范围，
  对象层产物（`pp`/`objs`/`strings`/`libs`/`classes`/`arrays`/`maps`）保持完整——它们是你
  挑选时的索引。

实测成本（真实 Flutter 应用 10 245 个函数）：全量 `--decompile` 导出 1.9 秒、写约 1000 个文件；
`dae info` / `dae getclass Foo` 0.03 秒，`dae disasm` 0.05 秒，最贵的 `dae callers`
（要扫全量调用点）0.18 秒。快照解析本身约 50 毫秒——渐进式省下的是写盘。

## 反编译器（实验性）

`dae --decompile` 额外产出 `dart/<库>.dart`：每个已命名函数一段伪代码，流程与同类工具
一致（机器相关 lift → 基本块 → 发射）。

**目前做到的**：

- 由 `cmp`/`fcmp`/`test` + 跳转折出的真条件（`if (rdx < 2)`）
- 框架寄存器名（`PP`/`THR`/`SP`/`FP`，以及各平台 profile 的 `register_aliases`），内存操作数内部也替换
- 直接调用目标带名字（`call router`）；没有名字的入口写成 `sub_0x...`
- **还原对象池常量**：`ldr x0, [PP, #0x17f8]` 写成 `x0 = "Hello" /* pp+0x17f8 */`
  （字符串字面量与立即数；非字符串条目给类型注释）。arm64 与 x64 都做过源码对照
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

**还没做的**：跨基本块的表达式合成（目前是块内若干层）、类型恢复（一切都是 `dynamic`，
字段访问是 `mem(base, disp)`）。认不出的指令原样输出为 `// unmapped:`，不做近似；
运行摘要里会打印这个行数——可以把它当质量刻度看。

每次改动都有门禁：`tests/dart_valid.rs`（真跑 `dart analyze`，要求零错误）与
`tests/decompiler_shape.rs`（产物文件花括号必须配平（不配平=静默丢分支）、函数体内语句必须正常
结束、结构化率有下限、**地址必须自洽**（函数末尾像终止符、直接调用命中函数入口））。
最后这条是本项目吃过亏补上的：Mach-O appended 快照的指令段定位曾经缺失，反编译器读的是
**别的代码**，而所有基于名字的指标却全是绿的。

## 已知限制

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