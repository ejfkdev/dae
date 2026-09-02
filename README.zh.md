# dae

[English](README.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/ejfkdev/dae)](https://github.com/ejfkdev/dae/releases/latest)
[![crates.io](https://img.shields.io/crates/v/dae-rs)](https://crates.io/crates/dae-rs)
[![Release CI](https://img.shields.io/github/actions/workflow/status/ejfkdev/dae/release.yml?label=build)](https://github.com/ejfkdev/dae/actions/workflows/release.yml)
[![Publish CI](https://img.shields.io/github/actions/workflow/status/ejfkdev/dae/publish.yml?label=publish)](https://github.com/ejfkdev/dae/actions/workflows/publish.yml)

> 配置驱动的 **Dart AOT 快照**调试信息导出工具。零依赖 Dart SDK、不运行目标程序：从 Mach-O / ELF / PE 中定位内嵌快照，导出与 [blutter](https://github.com/worawit/blutter) 一致的符号与结构。

适用于任意 Dart AOT 产物——Flutter release 构建、`dart compile exe`、`dart compile aot-snapshot`（Dart 2.7+ cluster 快照）。

## 特性

- **开箱即用、自动识别**——26 份 SDK profile 内嵌进二进制；按快照哈希匹配版本，自定义/Flutter 引擎构建走结构探针兜底。
- **快**——24 MB 的 Flutter 样本约 0.07 s 导出（≈Python 参考实现的 27 倍）。
- **双语 CLI**——中文语系输出中文，其余英文；`DAE_LANG=zh|en` 可强制指定。
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

规范见 [`docs/PROFILES.md`](docs/PROFILES.md)。

## 已知限制

- 地址是文件偏移空间，非运行时 VA（与 blutter 参考实现一致）
- `asm/` 的 IL 注释仅 arm64（x64 仅反汇编）
- 剥离 COFF 符号表的 PE 需先从 `.pdb` 回填符号
- Dart 1.24 / 2.0 是 JIT 快照，不支持

## 许可证

[MIT](LICENSE)