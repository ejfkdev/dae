# dae

[English](README.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/ejfkdev/dae)](https://github.com/ejfkdev/dae/releases/latest)
[![crates.io](https://img.shields.io/crates/v/dae-rs)](https://crates.io/crates/dae-rs)
[![Release CI](https://img.shields.io/github/actions/workflow/status/ejfkdev/dae/release.yml?label=release%20build)](https://github.com/ejfkdev/dae/actions/workflows/release.yml)

配置驱动的 Dart AOT 快照调试信息导出工具（Rust），零依赖 Dart SDK、不运行目标。从 Mach-O / ELF / PE 中定位快照，导出与 [blutter](https://github.com/worawit/blutter) 一致的调试数据。

**兼容所有 Dart AOT 产物**：Flutter release（iOS/Android/macOS/Windows/Linux）、`dart compile exe`、`dart compile aot-snapshot`——只要二进制嵌有 Dart 2.7+ 的 cluster 快照，不依赖任何框架。

- 函数名 ↔ 地址（library::class::method 三级归属，含混淆名还原）
- 对象池条目（`pp.txt`）、用户类实例递归 dump（`objs.txt`）
- radare2 命名脚本（`r2_script/addNames.r2` + `r2_dart_struct.h`）
- Frida 运行时 Classes 数组（`blutter_frida.js`）
- capstone 反汇编 + IL 伪指令注释（`asm/`，arm64）

## 安装

### 预编译 Release

从 [GitHub Releases](https://github.com/ejfkdev/dae/releases/latest) 下载对应平台二进制（Windows/macOS/Linux × x64/arm64 六个资产，x64 版已 UPX 压缩），解压即用。

macOS 产物为 ad-hoc 签名，若首次运行被 Gatekeeper 拦下，解除隔离属性即可：

```bash
xattr -dr com.apple.quarantine dae
```

### cargo

```bash
cargo install dae-rs                                # crates.io（首次 publish 后可用）
cargo install --git https://github.com/ejfkdev/dae  # 直接从 GitHub 仓库安装
```

两种方式装出的命令都是 `dae`。crates.io 包名为 `dae-rs`（`dae` 一名已被无关 crate
占用）；仓库名、库名、二进制命令保持 `dae` 不变。克隆源码后也可 `cargo install --path .`。

### Homebrew（macOS）

```bash
brew install ejfkdev/tap/dae
```

### 源码构建

```bash
cargo build --release
```

## 快速开始

```bash
dae <binary> <out_dir> [--sdk-profile <profile.json>]
```

26 个 SDK Profile 与平台 Profile **全部编译进二进制**，运行时无需任何 profile 文件。
Dart 版本自动识别：官方 SDK 构建的产物按快照版本指纹（32B hash，`version_hashes.json`）
精确命中；Flutter 引擎自编译/自定义构建走结构探针（alloc 试解析 + fill 打分）推断。
`--sdk-profile` / `--platform-profile` 仅用于特殊目标的强制覆盖。

## 版本支持

`profiles/sdk/` 内嵌 **26 个 Dart 版本**（1.24.3 → 3.14β），覆盖 cluster 快照格式全谱系。

| 版本范围 | 状态 | 说明 |
|---|---|---|
| 1.24.3 / 2.0.0 | unsupported | JIT 快照格式，非 AOT |
| 2.7.2 | objects 层 | ≤2.9 无指令表，仅对象层 |
| 2.10.4–2.14.4 | 地址层 | 函数名+地址可导出 |
| 2.15.0–2.17.0 | verified | 用户函数完整 |
| 2.16.2 / 2.18.1 / 2.19.6 | ELF 回填 | 函数名按 ELF 符号补偿 |
| 3.0.0–3.14β | verified | 用户函数完整 |

**21 单测全绿**（`cargo test`）。无已知 2.x/3.x 残余。

## 架构

三层分离，引擎不变，只加配置：

| 层 | 路径 | 内容 | 变化时 |
|---|---|---|---|
| 引擎 | `src/` | datastream 三种变长编码、cluster 流遍历、fill 解释器、命名还原、导出 writer | 不动 |
| SDK Profile | `profiles/sdk/*.json` | cid 枚举、cluster 字段布局（fill DSL）、tagging、runtime offsets | 每 Dart 版本一份 |
| 平台 Profile | `profiles/platform/*.json` | 容器解析器、符号名、寄存器角色 | 每 (容器 × 架构) 一份 |

规格：[`docs/PROFILES.md`](docs/PROFILES.md)

## 性能

macOS Flutter 样本（24MB → 14MB 产物）：**0.07s 墙钟**（Python 参考实现 1.9s，约 27×）。8 核并行（mimalloc 分配器、分块并行处理、填充解释器编译执行）。

## 已知边界

- 地址是文件偏移空间（非运行时 VA），与 blutter 参考实现一致
- asm IL 目前仅覆盖 arm64；x64 反汇编可输出但 IL 注释待补充
- PE 若剥掉 COFF 符号表，需先用 .pdb 回填符号
- 1.24/2.0 为 JIT 快照（`kMessageMagic`），不支持

## License

[MIT](LICENSE) · 第三方声明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)