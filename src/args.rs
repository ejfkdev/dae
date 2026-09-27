//! clap 定义的命令树。
//!
//! **为什么换成 clap**：手写 `while i < args.len()` 的解析器在同类工具里已经养出几类可复现的
//! bug——参考项目 ddc 的命令行就有：`getmethod -o` 是死代码（第一个循环先对未知 `-x` bail，
//! 后面读 `-o` 的循环永远到不了）；`info -d x app.apk` 把 `-d` 的取值当成输入路径（因为
//! "第一个不以 `-` 开头的参数就是输入"这条规则跑在自己的 flag 循环之前）；`callers` 解析了
//! `--dex` 又静默丢掉；文档声称查询大小写不敏感而代码是敏感的。这些不是疏忽，是
//! **「每个命令各写一遍参数循环」的必然结果**。clap 把「有哪些 flag」集中声明一次，
//! 位置参数与 flag 各自独立解析，上面前三类在结构上就不可能再发生。
//!
//! **但 `-h` 的输出仍然走本项目自己的双语文本**（[`crate::cli::help_for`]），不是 clap 自动
//! 生成的那份：项目自己的文本写了每个命令的**输出列格式**与**命名口径**（库名三种写法、
//! 函数名的下划线形式），比 clap 的通用 flag 列表有用得多，而且是双语的。所以这里
//! `disable_help_flag`，把 `-h/--help` 声明成普通 bool 交给 handler。
//!
//! 共享选项只声明一次（[`Common`]），各命令用 `#[command(flatten)]` 引入——这是 ddc 那
//! 9 处重复 `--dex` 转发块的反面。

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "dae",
    // 帮助与版本都由 main.rs 先截获（要出双语文本），不让 clap 接管
    disable_help_flag = true,
    disable_version_flag = true,
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// full or filtered export: every artifact under <out_dir>
    Export(Export),

    /// snapshot / SDK / size overview
    Info(Query),
    /// library (package) listing with counts
    Libs(Query),
    /// class listing
    Classes(Query),
    /// function listing (entry / size / owner)
    Functions(Query),
    /// top-N functions by size
    Largest(Query),

    /// string table search
    Strings(Query),
    /// named fields (source + byte offset)
    Fields(Query),

    /// who calls it
    Callers(Target),

    /// raw disassembly (arm64 with IL comments)
    Disasm(Target),

    /// decompile one class
    Getclass(Target),
    /// decompile one method
    Getmethod(Target),
    /// decompile one library (package); a prefix selects the whole package
    Getlib(Target),

    /// this guide (bilingual), or `dae help <cmd>` for one command
    Help(Help),
    /// print name and version
    Version,
}

/// 所有子命令共享的选项。
///
/// `-f/--find` 目前只有 `strings` 用；放在共享组里是**为了与手写解析器时代的行为一致**
/// （那时 `parse_opts` 对所有命令都接受它、其余命令忽略）。收紧它会让今天能跑的命令行
/// 变成错误，所以这一步不动。
#[derive(Args, Clone, Default)]
pub struct Common {
    /// show this command's help (bilingual)
    #[arg(short = 'h', long = "help")]
    pub help: bool,

    /// force an SDK profile (default: embedded, auto-detected by version fingerprint)
    #[arg(long = "sdk-profile", value_name = "PATH")]
    pub sdk_profile: Option<PathBuf>,

    /// force a platform profile (default: auto by container + arch)
    #[arg(long = "platform-profile", value_name = "PATH")]
    pub platform_profile: Option<PathBuf>,

    /// write to PATH instead of stdout; `-o -` is the same as stdout
    #[arg(short = 'o', long = "output", value_name = "PATH")]
    pub output: Option<String>,

    /// cap the number of rows printed
    #[arg(short = 'n', long = "limit", value_name = "N")]
    pub limit: Option<usize>,

    /// filter text (strings)
    #[arg(short = 'f', long = "find", value_name = "TEXT")]
    pub find: Option<String>,

    /// only these libraries (repeatable; a prefix = whole package)
    #[arg(long = "lib", value_name = "PATTERN")]
    pub lib: Vec<String>,

    /// only these classes (repeatable)
    #[arg(long = "class", value_name = "PATTERN")]
    pub class: Vec<String>,

    /// only these functions (repeatable; Class.method works)
    #[arg(long = "func", value_name = "PATTERN")]
    pub func: Vec<String>,

    /// make the patterns substring matches (default: exact)
    #[arg(long = "fuzzy")]
    pub fuzzy: bool,
}

/// `<binary> [pattern]` —— 清单类命令的共同形状。
///
/// 七个命令共用这一个结构，所以它们的参数语义**不可能各自漂移**（手写时代每个命令一个
/// 循环，正是漂移的来源）。
#[derive(Args)]
#[command(disable_help_flag = true)]
pub struct Query {
    #[command(flatten)]
    pub common: Common,

    /// target binary (Mach-O/ELF/PE with a Dart AOT snapshot; .app/.framework accepted)
    pub binary: String,

    /// optional name filter
    pub pattern: Option<String>,
}

/// `<binary> <name>` —— 单目标命令的共同形状。
#[derive(Args)]
#[command(disable_help_flag = true)]
pub struct Target {
    #[command(flatten)]
    pub common: Common,

    /// target binary (Mach-O/ELF/PE with a Dart AOT snapshot; .app/.framework accepted)
    pub binary: String,

    /// what to look up: a name, or 0xADDRESS where the command accepts one
    pub name: String,
}

/// `<binary> <out_dir> [--decompile]`
#[derive(Args)]
#[command(disable_help_flag = true)]
pub struct Export {
    #[command(flatten)]
    pub common: Common,

    /// target binary (Mach-O/ELF/PE with a Dart AOT snapshot; .app/.framework accepted)
    pub binary: String,

    /// output directory (created if missing)
    pub out_dir: String,

    /// also emit dart/ pseudocode
    #[arg(long = "decompile")]
    pub decompile: bool,
}

/// `help [cmd]`
#[derive(Args)]
#[command(disable_help_flag = true)]
pub struct Help {
    /// command to show help for; omit for the whole guide
    pub cmd: Option<String>,
}
