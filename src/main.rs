//! Dart AOT 快照调试信息导出工具（配置驱动）。
//!
//! 用法:
//!   dae <binary> <out_dir> [--sdk-profile P] [--platform-profile P] [--decompile]
//!   dae <subcommand> <binary> [...]      # 渐进式，见 `dae help`
//!
//! 本文件只负责三件事：选语言、截获 `-h`/`-V`（要出双语文本）、把快捷形式补成
//! `export` 子命令后交给 clap。命令树声明在 `src/args.rs`，实现在 `src/cli.rs`。

use clap::Parser;

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    let lang = dae::locale::detect();
    let s = dae::locale::messages(lang);
    let args: Vec<String> = std::env::args().skip(1).collect();

    // 无参数、`-h`、`--help`、`help` 四种形态打印**同一份**文本并以 0 退出。
    //
    // 无参数为什么是 0 而不是 2：它不是一个失败的调用，而是「我想知道怎么用」，
    // 与 `-h` 语义相同。文本用本项目自己的双语版（[`dae::cli::help`]）而不是 clap 自动
    // 生成的那份——项目自己的文本写了每条命令的输出列格式与命名口径，而 clap 只会列 flag。
    //
    // ⚠️ 这里以前有一份**独立的** `print_help`，与 `cli::help` 各写一遍：`-h` 出 50 行、
    // `dae help` 出 64 行，子命令表只在后者里完整。同一份文档写两遍就只会更新一遍，
    // 现在只剩 `cli::help` 一处。
    if args.is_empty() {
        println!("{}", dae::cli::help(lang));
        std::process::exit(0);
    }
    match args[0].as_str() {
        "-h" | "--help" => {
            println!("{}", dae::cli::help(lang));
            std::process::exit(0);
        }
        "-V" | "--version" => {
            println!("dae {}", env!("GIT_VERSION"));
            std::process::exit(0);
        }
        _ => {}
    }

    // 快捷形式：第一个参数不是已知子命令 ⇒ 当成 `export` 的参数。
    // 于是 `dae App.app out/ --decompile` 与 `dae export App.app out/ --decompile` 完全等价。
    // 本机恰好有个叫 `info` 的文件时写 `./info` 即可落回全量导出（与既有口径一致）。
    //
    // 顺带修掉一个歧义：以前 `dae bogus App.app out/` 会把 `bogus` 当二进制路径去读、
    // 报 "failed to read binary" 并 exit 1；现在 clap 报「unrecognized subcommand」并 exit 2，
    // 即用法错误该有的退出码。（参考项目 ddc 因为把判定放在路径解析之后，至今仍是前一种。）
    //
    // ⚠️ `try_parse_from` 把**第 0 个元素当程序名**，所以这里必须自己补上 "dae"——
    // 少补一个会让 `dae info` 被读成「程序名 info、缺子命令」。
    let mut argv: Vec<String> = Vec::with_capacity(args.len() + 2);
    argv.push("dae".to_string());
    if !dae::cli::is_subcommand(&args[0]) {
        argv.push("export".to_string());
    }
    argv.extend(args);

    let cli = match dae::args::Cli::try_parse_from(&argv) {
        Ok(c) => c,
        Err(e) => {
            // clap 的用法错误文本只有英文（clap 自身无 i18n）。保留它精确的诊断
            // （哪个参数、期望什么、正确的 usage 行），另加一行双语指路，
            // 免得中文用户只看到英文。
            //
            // 退出码 **2 = 用法错误**，与本项目既有口径一致；手写解析器时代
            // `dae info bin --nope` 报的是 1，把用法错误混进了运行期错误。
            eprintln!(
                "{}: {}",
                s.err_prefix,
                lang.pick(
                    "用法错误（`dae help` 列出全部命令与选项）",
                    "usage error (`dae help` lists every command and option)"
                )
            );
            e.exit()
        }
    };
    std::process::exit(dae::cli::run_cmd(cli.cmd, lang, &s));
}
