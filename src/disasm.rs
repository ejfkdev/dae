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
#[cfg(feature = "asm")]
use crate::analyzer::Analyzer;

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

/// 扫描时回调拿到的「当前函数」。按值传给回调（每条指令一次），所以要 `Copy`。
#[derive(Clone, Copy)]
pub struct ScanFn<'a> {
    /// 运行时入口地址
    pub ep: u64,
    /// 完整名（`lib/Class.member`）
    pub name: &'a str,
}

/// 并行扫描一批函数的每条指令。
///
/// `plan` 的每条是 `(ep, payload, csize, full_name)`，即 `callgraph::plan_functions` 的形状。
/// `visit` 对每条指令调一次，返回 `Some(T)` 就收下。
///
/// **并行但确定**：按 plan 切成连续区间、每线程一段，回收时按区间序号拼接，所以同一份输入
/// 永远得到同一份输出。查询命令的结果要能进对拍与门禁，这条性质是前提。
///
/// 线程数、capstone 构造、边界检查都走本模块的共享基元——`export::callgraph::collect_edges`
/// 是同一套逻辑的另一份消费者（它因为要按区间回收 `Vec<Edge>` 而保留自己的循环，
/// 但引擎与边界检查已经共用）。
pub fn scan_instructions<T, F>(
    analyzer: &Analyzer,
    plan: &[(u64, u64, u64, String)],
    visit: F,
) -> Result<Vec<T>, String>
where
    T: Send + 'static,
    F: Fn(ScanFn<'_>, &capstone::Insn) -> Option<T> + Sync,
{
    let is_arm64 = analyzer.platform.arch == "arm64";
    let n_threads = crate::analyzer::n_threads();
    let chunk = plan.len().div_ceil(n_threads).max(1);
    let ranges: Vec<(usize, usize)> = (0..plan.len())
        .step_by(chunk)
        .map(|b| (b, (b + chunk).min(plan.len())))
        .collect();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        for (pi, &(b, e)) in ranges.iter().enumerate() {
            let tx = tx.clone();
            let visit = &visit;
            scope.spawn(move || {
                let cs = match build_cs(is_arm64) {
                    Ok(c) => c,
                    Err(err) => {
                        let _ = tx.send((pi, Vec::new(), Some(err)));
                        return;
                    }
                };
                let mut out: Vec<T> = Vec::new();
                for (ep, payload, csize, name) in &plan[b..e] {
                    let Some((_foff, code)) =
                        function_code(analyzer.data, analyzer.slice_off, *payload, *csize)
                    else {
                        continue;
                    };
                    // 反汇编地址是 payload（运行时入口），不是文件偏移——见 function_code
                    let Ok(insns) = cs.disasm_all(code, *payload) else {
                        continue;
                    };
                    let ctx = ScanFn {
                        ep: *ep,
                        name: name.as_str(),
                    };
                    for ins in insns.iter() {
                        if let Some(v) = visit(ctx, ins) {
                            out.push(v);
                        }
                    }
                }
                let _ = tx.send((pi, out, None));
            });
        }
        drop(tx);
    });
    let mut parts: Vec<Option<Vec<T>>> = (0..ranges.len()).map(|_| None).collect();
    let mut err: Option<String> = None;
    for (pi, v, e) in rx {
        parts[pi] = Some(v);
        if e.is_some() && err.is_none() {
            err = e;
        }
    }
    if let Some(e) = err {
        return Err(e);
    }
    let total: usize = parts.iter().flatten().map(|v| v.len()).sum();
    let mut all = Vec::with_capacity(total);
    for p in parts.into_iter().flatten() {
        all.extend(p);
    }
    Ok(all)
}
