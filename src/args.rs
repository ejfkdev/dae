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
//! ⚠️ **代价：位置参数必须声明成 `Option<String>`，由 handler 自己校验。** 因为 clap 的
//! 必填位置参数校验发生在解析阶段、**早于** handler，于是 `dae libs -h` 会先撞上
//! 「required arguments were not provided: <BINARY>」而以 2 退出，`-h` 永远没机会执行——
//! 18 个子命令全部如此（`dae help libs` 反而是好的，因为它没有必填位置参数）。
//! 自己校验换来两样东西：`<cmd> -h` 在缺参数时也能出帮助；错误文本可以是双语的、
//! 并且指向 `dae help <cmd>`。顺带修掉一个更难看的副作用：clap 把我们的 `-h` 当成一个
//! 名叫 `help` 的普通 flag，于是它生成的 usage 行印成 `dae libs --help <BINARY> [PATTERN]`，
//! 看起来像 `--help` 是必填项。
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

    /// object pool entries (what `text/pp.txt` dumps)
    Pp(Query),
    /// user class instances with their field values
    Objs(Query),
    /// instruction-table entries no Function object references
    Stubs(Query),

    /// method/field name search, optionally scoped to one class
    Members(Members),
    /// who calls it
    Callers(Target),
    /// what it calls
    Callees(Target),
    /// every code site that loads a given string literal / object kind from the pool
    Findrefs(FindRefs),

    /// raw disassembly (arm64 with IL comments)
    Disasm(Target),

    /// decompile one class
    Getclass(Target),
    /// decompile one method
    Getmethod(Target),
    /// decompile one library (package); a prefix selects the whole package
    Getlib(Target),
    /// decompile everything (stdout by default), without writing any other artifact
    Decompile(Decompile),

    /// this guide (bilingual), or `dae help <cmd>` for one command
    Help(Help),
    /// print name and version
    Version(VersionArgs),
}

/// `version`
///
/// 只为了 `-h/--help` 存在：`dae version -h` 与其它 21 个子命令保持一致的行为，
/// 而不是报「unexpected argument '-h' found」。
#[derive(Args)]
#[command(disable_help_flag = true)]
pub struct VersionArgs {
    /// show this command's help (bilingual)
    #[arg(short = 'h', long = "help")]
    pub help: bool,
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

    /// exclude these libraries (repeatable; same prefix rule as --lib)
    #[arg(long = "exclude-lib", value_name = "PATTERN")]
    pub exclude_lib: Vec<String>,

    /// exclude SDK libraries (those whose URL starts with `dart:`)
    #[arg(long = "no-sdk")]
    pub no_sdk: bool,

    /// exclude the SDK and the Flutter framework (`dart:` and `package:flutter`)
    #[arg(long = "app", conflicts_with = "no_sdk")]
    pub app: bool,
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
    pub binary: Option<String>,

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
    pub binary: Option<String>,

    /// what to look up: a name, or 0xADDRESS where the command accepts one
    pub name: Option<String>,
}

/// `<binary> <out_dir> [--decompile]`
#[derive(Args)]
#[command(disable_help_flag = true)]
pub struct Export {
    #[command(flatten)]
    pub common: Common,

    /// target binary (Mach-O/ELF/PE with a Dart AOT snapshot; .app/.framework accepted)
    pub binary: Option<String>,

    /// output directory (created if missing)
    pub out_dir: Option<String>,

    /// also emit dart/ pseudocode
    #[arg(long = "decompile")]
    pub decompile: bool,
}

/// `members <binary> [NAME] [--class X] [--method|--field]`
///
/// `--class` 复用共享选项（与其它命令的筛选语义一致），`--method`/`--field` 互斥。
#[derive(Args)]
#[command(disable_help_flag = true)]
pub struct Members {
    #[command(flatten)]
    pub common: Common,

    /// target binary (Mach-O/ELF/PE with a Dart AOT snapshot; .app/.framework accepted)
    pub binary: Option<String>,

    /// optional name filter (substring)
    pub pattern: Option<String>,

    /// only methods
    #[arg(long = "method", conflicts_with = "field")]
    pub method: bool,

    /// only fields
    #[arg(long = "field")]
    pub field: bool,
}

/// `findrefs <binary> <kind> <query>`
///
/// kind 只有两种，都是**可证**的检索面：`string TEXT`（池里的字符串字面量，按子串）与
/// `kind NAME`（对象种类，即反编译产物里 `/* TypeArguments */` 那个词，整名精确）。
///
/// **不提供 `field`**：编译后的机器码里没有符号化的字段引用，只剩裸位移，按位移匹配会把
/// 大量无关的 `[x, #0x18]` 当成命中——那是猜，不是查。
/// **也不叫 `type`**：池条目的描述形是 `Kind: 内容`，那个前缀是对象**类别**而不是类型名；
/// 拿它当类型名检索会既漏又误（搜 `Field` 命中的是所有 Field 对象，与具体哪个字段无关）。
/// 宁可少一个 kind，也不给一个会骗人的结果。
#[derive(Args)]
#[command(disable_help_flag = true)]
pub struct FindRefs {
    #[command(flatten)]
    pub common: Common,

    /// target binary (Mach-O/ELF/PE with a Dart AOT snapshot; .app/.framework accepted)
    pub binary: Option<String>,

    /// what to look for: `string` (pool string literals) or `kind` (object kind)
    pub kind: Option<String>,

    /// the text to search (substring) or the object kind name (exact)
    pub query: Option<String>,
}

/// `decompile <binary> [-o DIR|FILE.dart|-]`
///
/// 只反编译，不写 ida/r2/asm/text 那些产物。无 `-o` 时走 **stdout**（与 `get*` 一致），
/// 这是「把整个应用的伪代码灌进管道」的唯一入口——全量导出必须给 out_dir。
#[derive(Args)]
#[command(disable_help_flag = true)]
pub struct Decompile {
    #[command(flatten)]
    pub common: Common,

    /// target binary (Mach-O/ELF/PE with a Dart AOT snapshot; .app/.framework accepted)
    pub binary: Option<String>,
}

/// `help [cmd]`
#[derive(Args)]
#[command(disable_help_flag = true)]
pub struct Help {
    /// show this command's help (bilingual)
    #[arg(short = 'h', long = "help")]
    pub help: bool,

    /// command to show help for; omit for the whole guide
    pub cmd: Option<String>,
}
