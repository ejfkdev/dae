# Third-Party Notices

dae 本身以 MIT 协议发布（见根目录 `LICENSE`）。本文件列出随仓库分发内容的第三方来源与协议。

## blutter

`templates/frida.template.js` 与 `templates/r2_dart_struct.h` 派生自
[blutter](https://github.com/worawit/blutter)。

- 协议：MIT License
- Copyright (c) 2023 Worawit Wangwarunyoo
- 原始版权声明已保留于上述模板文件头部
- `ida_script/addNames.py` 的脚本结构与函数命名格式对齐 blutter 的 Dump4IDA
  约定（格式对齐，非代码复制）

## Dart SDK

`profiles/sdk/*.json` 由对应版本 [Dart SDK](https://github.com/dart-lang/sdk)
（`runtime/vm/` 源码）机械生成（生成器位于本地工作区，不入库），属对 BSD 协议
源码派生的数据（字段布局、枚举值等事实性信息）。

- 协议：BSD 3-Clause License
- Copyright (c) The Dart project authors. See the Dart SDK `LICENSE` file.

## Rust 依赖

`serde` / `serde_json` / `mimalloc` / `capstone`（可选 feature）的协议见各自
crate 的 license 元数据（`cargo` 解析后的 `Cargo.lock` 与 crates.io 页面）。