//! 反汇编层的共享基元：capstone 引擎，以及「取一个函数的机器码切片」。
//!
//! 抽出来是因为这两样原本各有 2–3 份副本，而且**已经漂移**：
//!
//! * `build_cs` 有三份（`decompiler`、`export::asm`、`export::callgraph`），设置全都一样
//!   （arm64 或 x86-64 Intel、`detail(false)`、`skipdata(true)`）。「必须一致的设置」分散在
//!   三处就是漂移的起点——`export::asm` 那份只有 arm64 分支，另两份有 x86 分支。
//! * 取切片的边界检查有两份，其中 `export::asm` 的两处（job 规划与 `render_one`）是
//!   `foff as usize + csize as usize` 这种**裸加法**，而 `export::callgraph` 那份专门写了注释
//!   说明「避免任何加法回绕，回绕会绕过 `> data.len()` 检查」。**同一个教训只落在一处。**
//!
//! 合成一处后，每条纪律（detail 必须关、边界必须防回绕）只需要在一个地方成立。

#[cfg(feature = "asm")]
use capstone::arch::{BuildsCapstone, BuildsCapstoneSyntax};
#[cfg(feature = "asm")]
use capstone::{arch, Capstone};

/// 建 capstone 引擎（arm64 或 x86-64 Intel 语法）。
///
/// **`.detail(false)`**：全仓库只用 `mnemonic()` / `op_str()` / `address()` / `bytes()`，
/// 从不调 `insn_detail()` / `arch_detail()` / `operands()`（已 grep 确认零处）。detail 模式会让
/// capstone 为每条指令额外解析并存储完整操作数结构，是反汇编的主要开销之一。
/// 改这一项必须用「产物逐字节对拍」验证，不能只看它编译过。
///
/// **`skipdata(true)`**：函数入口前常带 0 填充/对齐字节，遇到非指令字节要还原成 `.byte ..`
/// 继续，否则**一个坏字节会让整个函数从产物里消失**（实测 `dart compile exe` 的部分函数
/// 入口前就带 16 字节 0）。
#[cfg(feature = "asm")]
pub fn build_cs(is_arm64: bool) -> Result<Capstone, String> {
    let c = if is_arm64 {
        Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(false)
            .build()
    } else {
        Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(false)
            .build()
    }
    .map_err(|e| format!("capstone 初始化失败: {e}"))?;
    let mut c = c;
    c.set_skipdata(true)
        .map_err(|e| format!("capstone skipdata 设置失败: {e}"))?;
    Ok(c)
}

/// 取一个函数的机器码切片，返回 `(文件偏移, 切片)`；越界或加法回绕则 `None`。
///
/// ⚠️ 反汇编时要传给 capstone 的**地址是 `payload`（运行时入口），不是这里返回的文件偏移**。
/// 三处调用点都是 `disasm_all(code, payload)`。本函数只负责切片与边界，不代替调用方决定地址
/// ——把两者混为一谈正是「反汇编到别的字节上」那类错位的来源，而那种错位**指标看不见**：
/// 函数名来自 Code 对象、结构化率与能否过分析都照常正常（本项目踩过三次，见
/// `docs/DECOMPILER.md` 的「这张表反复踩的同一个坑」）。
///
/// `slice_off + payload` 与 `foff + csize` 都用 `checked_add`：裸加法回绕后会变成一个很小的数，
/// 于是绕过 `> data.len()` 检查、切出一段无关字节。
#[cfg(feature = "asm")]
pub fn function_code(
    data: &[u8],
    slice_off: u64,
    payload: u64,
    csize: u64,
) -> Option<(u64, &[u8])> {
    let foff = slice_off.checked_add(payload)?;
    let end = foff.checked_add(csize)?;
    if end > data.len() as u64 {
        return None;
    }
    Some((foff, &data[foff as usize..end as usize]))
}
