# dae

[English](README.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/ejfkdev/dae)](https://github.com/ejfkdev/dae/releases/latest)
[![crates.io](https://img.shields.io/crates/v/dae-rs)](https://crates.io/crates/dae-rs)
[![Release CI](https://img.shields.io/github/actions/workflow/status/ejfkdev/dae/release.yml?label=release%20build)](https://github.com/ejfkdev/dae/actions/workflows/release.yml)
[![Publish CI](https://img.shields.io/github/actions/workflow/status/ejfkdev/dae/publish.yml?label=crates.io%20publish)](https://github.com/ejfkdev/dae/actions/workflows/publish.yml)

> 配置驱动的 Dart AOT 快照调试信息导出工具。零依赖 Dart SDK、不运行目标程序：从 Mach-O / ELF / PE 中定位快照，导出与 [blutter](https://github.com/worawit/blutter) 一致的调试数据。

**兼容所有 Dart AOT 产物**——Flutter release（iOS/Android/macOS/Windows/Linux）、`dart compile exe`、`dart compile aot-snapshot`——只要二进制嵌有 Dart 2.7+ 的 cluster 快照。

- **免配置、自动识别**：26 版 SDK Profile 全部内嵌在二进制里，Dart 版本自动识别（快照版本指纹精确命中；Flutter 引擎自编译/自定义构建走结构探针兜底）
- **快**：24 MB 的 Flutter 样本约 **0.07 秒**导出完成（约为 Python 参考实现的 27×）
- **双语 CLI**：输出跟随系统语系——中文语系（简体/繁体）输出中文，其余输出英文；`DAE_LANG=zh|en` 可强制
- **零框架依赖**：直接解析三种容器格式，无需 Dart SDK / Flutter 工具链

## 安装

### 预编译 Release

从 [GitHub Releases](https://github.com/ejfkdev/dae/releases/latest) 下载对应平台二进制（Windows/macOS/Linux × x64/arm64，x64 版已 UPX 压缩）。

macOS 产物为 ad-hoc 签名，若首次运行被 Gatekeeper 拦下：

```bash
xattr -dr com.apple.quarantine dae
```

### Homebrew（macOS）

```bash
brew install ejfkdev/tap/dae
```

### cargo

```bash
cargo install dae-rs                                # crates.io（首次 publish 后可用）
cargo install --git https://github.com/ejfkdev/dae  # 或直接从本仓库安装
```

两种方式装出的命令都是 `dae`。（crates.io 包名为 `dae-rs` 是因 `dae` 一名已被占用；仓库、库名、二进制命令均保持 `dae`。）

### 源码构建

```bash
cargo build --release
```

## 使用

```bash
dae <binary> <out_dir> [--sdk-profile <profile.json>]
```

示例——编译一段小 Dart 程序并导出：

```bash
$ dart compile exe demo.dart -o demo
$ dae demo out
SDK Profile: dart/3.13.0（版本指纹命中）
目标: /path/to/demo (macho arm64)
导出完成 → out:
  r2_script/addNames.r2     5 条函数名/地址
  ida_script/addNames.py    1175 个函数命名 + Dart 结构头
  frida.js                  617 个 Classes 条目
  asm/                      5 个函数反汇编 + IL
  pp.txt                    1424 个对象池条目
  objs.txt                  17 个用户类实例
```

导入 IDA：`File → Script file…` 选择 `ida_script/addNames.py`——函数名、函数边界与 `DartThread`/`DartObjectPool` 结构自动落入当前数据库（装载基址自动重定）。radare2：`r2 -i r2_script/addNames.r2 <binary>`，随后 `to r2_dart_struct.h` 载入结构头。

## 导出产物

| 产物 | 用途 |
|---|---|
| `ida_script/addNames.py` | IDAPython 脚本：函数命名 + 边界 + Dart 结构 |
| `r2_script/addNames.r2` | radare2 flag/注释脚本（库 → 类 → 方法三层） |
| `r2_script/r2_dart_struct.h` | Dart 结构布局（IDA 侧另有 `ida_script/ida_dart_struct.h`） |
| `frida.js` | Frida 模板 + 运行时 Classes 数组 |
| `asm/` | capstone 反汇编 + blutter 风格 IL 注释（arm64） |
| `pp.txt` / `objs.txt` | 对象池条目 / 用户类实例递归 dump |

## 使用导出产物

### IDA

1. 在 IDA 中打开目标二进制，等待初始自动分析完成
2. `File → Script file…` 选择 `ida_script/addNames.py`——函数命名与边界落入当前数据库，`DartThread`/`DartObjectPool` 结构自动解析入库（脚本自动按装载基址重定）
3. 验证：跳转到脚本里打印的地址（或任意已命名函数）；结构在 `View → Open subviews → Structures` 中可见

脚本同时载入 `ida_script/ida_dart_struct.h`——定义 Dart 运行时布局（`DartThread`、`DartObjectPool` 等）的静态 C 头，用于在 IDA 里给 Dart 对象套结构。该头文件派生自 blutter，文件内的 MIT 归因头是许可证要求，需保留。

### radare2

```bash
r2 -i out/r2_script/addNames.r2 <binary>      # 库/类/方法变成 flag
# 会话内:
to out/r2_script/r2_dart_struct.h             # 载入 Dart 结构头
f~method.                                     # 浏览 flag
```

### Frida

`frida.js` 是**模板**：把标记的 hook 行/地址换成你要挂钩的入口（从命名函数里挑一个），然后：

```bash
frida -f <app> -l out/frida.js
```

`Classes` 数组提供逐类元数据（字段位图、大小、参数偏移），可用于构造 hook。

### 文本产物

- `asm/*.dart`——按库一份的反汇编，带 blutter 风格 IL 伪指令注释；纯文本，直接阅读或检索
- `pp.txt`——对象池条目（立即数、对象引用、native/stub）；用于找内嵌数据与常量
- `objs.txt`——用户类实例递归 dump（super 链、bool/List/Map 内容）；用于还原运行时对象值

## Dart 版本支持

| 版本范围 | 状态 |
|---|---|
| 3.0.0 – 3.14β | ✅ verified——用户函数完整 |
| 2.15.0 – 2.17.0 | ✅ verified——用户函数完整 |
| 2.10.4 – 2.14.4 | 函数名 + 地址可导出 |
| 2.7.2 | 仅对象层 |
| 1.24.3 / 2.0.0 | ❌ JIT 快照格式（非 AOT） |

## 工具兼容性

| 工具 | 状态 |
|---|---|
| IDA 9.3 / 9.4 | ✅ 真机端到端实测（命名 + 结构） |
| IDA 8.x | 预期兼容（同一批 API 自 7.x 存在；本机未装 8.x 实跑） |
| radare2 6.2 | ✅ 实测——脚本零错误、flag 与注释正常落地 |
| radare2 5.x | 预期兼容（仅用长期稳定命令） |
| rizin | 可解析执行；其「每地址单 flag」模型会跳过同址辅助标志（已如实注明） |
| Frida 14 – 17 | 只依赖核心 API（`Interceptor`/`Module`/`ptr`）；运行时注入请在你的目标上验证 |

## 工作原理

三层分离，引擎跨版本不变，只加配置：

| 层 | 路径 | 内容 |
|---|---|---|
| 引擎 | `src/` | 变长编码、cluster 流遍历、fill 解释器、命名还原、导出 writer |
| SDK Profile | `profiles/sdk/*.json` | cid 枚举、cluster 字段布局（fill DSL）、tagging、runtime offsets——每 Dart 版本一份 |
| 平台 Profile | `profiles/platform/*.json` | 容器解析器、符号名、寄存器角色——每（容器 × 架构）一份 |

规格：[`docs/PROFILES.zh.md`](docs/PROFILES.zh.md)

## 已知边界

- 地址是文件偏移空间（非运行时 VA），与 blutter 参考实现一致
- `asm/` 的 IL 注释仅覆盖 arm64；x64 可输出反汇编但 IL 注释待补充
- PE 若剥掉 COFF 符号表，需先用 .pdb 回填符号
- Dart 1.24 / 2.0 为 JIT 快照（`kMessageMagic`），不支持

## License

[MIT](LICENSE)