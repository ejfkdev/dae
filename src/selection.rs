//! 选择性反编译的筛选条件：`--lib` / `--class` / `--func` 三个模式串，
//! 以及子命令（getclass / getmethod / getlib）单目标匹配。
//!
//! 匹配口径（写下来是因为它决定用户能不能「猜中」）：
//! * **库名先规范化**：`$`→`/`、去掉 `package:` 前缀与结尾的 `.dart`、`::`→`/`，
//!   于是 `testing_app$screens$home`、`package:testing_app/screens/home.dart`、
//!   `testing_app_screens_home` 三者指向同一个库（分别来自 functions.txt、libs.txt
//!   与 dart/ 产物文件名）。
//! * **库按前缀也算命中**：`--lib testing_app` 选中 `testing_app/*` 全部——这正是
//!   「按包反编译」想要的语义。
//! * **类名/函数名默认精确**（大小写敏感 → 大小写不敏感），加 `--fuzzy` 后才是子串匹配。
//!   不默认模糊，是因为 `_anon_closure` 之类的名字太容易误命中。
//! * 函数名可写 `Class.method`、`lib/Class.method` 或裸 `method`；逐个后缀比对。

use crate::analyzer::LibGroups;

#[derive(Debug, Default, Clone)]
pub struct Selection {
    pub libs: Vec<String>,
    pub classes: Vec<String>,
    pub funcs: Vec<String>,
    /// 类名/函数名改为子串匹配（库名本来就是前缀匹配）
    pub fuzzy: bool,
    /// **排除**这些库（`--exclude-lib`，以及 `--no-sdk` / `--app` 解析出来的库名）。
    ///
    /// 匹配口径与 `libs` 完全相同（精确 / 加 `/` 的前缀 / fuzzy 时子串），所以
    /// `--exclude-lib dart_core` 不会误伤一个叫 `dart_core_extra` 的包——前缀规则要求
    /// 后面紧跟分隔符。这条性质很重要：`--no-sdk` 解析出来的就是一批 `dart_*` 名字。
    pub exclude_libs: Vec<String>,
}

impl Selection {
    pub fn is_empty(&self) -> bool {
        self.libs.is_empty()
            && self.classes.is_empty()
            && self.funcs.is_empty()
            && self.exclude_libs.is_empty()
    }

    pub fn any_lib(&self, lib: &str) -> bool {
        if self.libs.is_empty() {
            return true;
        }
        let l = norm_lib(lib);
        self.libs.iter().any(|p| {
            let p = norm_lib(p);
            l == p || l.starts_with(&format!("{p}/")) || (self.fuzzy && l.contains(&p))
        })
    }

    /// 这个库是否被排除。口径与 [`Selection::any_lib`] 对称（同一套规范化与前缀规则），
    /// 只是语义相反——两边不一致的话，「选中」与「排除」会互相说不清谁赢。
    pub fn lib_excluded(&self, lib: &str) -> bool {
        if self.exclude_libs.is_empty() {
            return false;
        }
        let l = norm_lib(lib);
        self.exclude_libs.iter().any(|p| {
            let p = norm_lib(p);
            l == p || l.starts_with(&format!("{p}/")) || (self.fuzzy && l.contains(&p))
        })
    }

    pub fn any_class(&self, cls: &str) -> bool {
        if self.classes.is_empty() {
            return true;
        }
        self.classes
            .iter()
            .any(|p| name_hit(p, cls, self.fuzzy))
    }

    pub fn any_func(&self, lib: &str, cls: &str, mangled: &str) -> bool {
        if self.funcs.is_empty() {
            return true;
        }
        // 候选写法要覆盖「用户看到什么就抄什么」：
        //   mangled（deposit）、Class.method（Account.deposit）、lib/Class.method、
        //   **产物里的下划线形式**（Account_deposit，dart/ 与 asm/ 的函数标题），
        //   以及 **call_edges.txt / callers / findrefs 的全点号形式**（lib.Class.method）。
        // 少最后一种，用户从那些输出里复制函数名回来查就会落空——实测
        // `dae findrefs … | 取 from 列` 喂给 `dae disasm` 会报 nothing matched，下钻链就断了。
        // 少下划线那种同样会断（门禁 tests/cli.rs 抓到过）。
        let full_lib = norm_lib(lib);
        let mut cands: Vec<String> = vec![mangled.to_string()];
        if !cls.is_empty() {
            cands.push(format!("{cls}.{mangled}"));
            cands.push(format!("{full_lib}/{cls}.{mangled}"));
            // 全点号：`plan_functions` 就是用这个形式造名字的，所以它进了
            // text/call_edges.txt 与 callers/callees/findrefs 的输出。
            // 两种库名写法都收：原样的（testing_app$screens$home）与规范化的
            // （testing_app/screens/home，即 URL 去掉 package: 后的样子）。
            // 注意 `dart:` 库不适用后者——library_name 把 dart:core 写成 dart_core，
            // 而 norm_lib 又会把 `dart:` 前缀剥掉，所以只能用原样那一支。
            cands.push(format!("{lib}.{cls}.{mangled}"));
            cands.push(format!("{full_lib}.{cls}.{mangled}"));
            let artifacts = format!("{}_{}", cls.replace(['.', ':'], "_"), mangled);
            cands.push(artifacts.trim_start_matches('_').to_string());
            cands.push(format!(
                "{}_{}",
                full_lib.replace(['/', ':'], "_"),
                cls.replace(['.', ':'], "_")
            )
            .trim_end_matches('_')
            .to_string());
        } else {
            cands.push(format!("{full_lib}.{mangled}"));
            cands.push(format!("{lib}.{mangled}"));
        }
        let cands: Vec<String> = cands.into_iter().filter(|c| !c.is_empty()).collect();
        self.funcs
            .iter()
            .any(|p| cands.iter().any(|c| name_hit(p, c, self.fuzzy)))
    }

    pub fn hit(&self, lib: &str, cls: &str, mangled: &str) -> bool {
        self.any_lib(lib) && self.any_class(cls) && self.any_func(lib, cls, mangled)
    }
}

/// 库名规范化：`package:testing_app/screens/home.dart` → `testing_app/screens/home`
pub fn norm_lib(lib: &str) -> String {
    let mut s = lib.trim();
    for pre in ["package:", "dart:", "file://"] {
        if let Some(r) = s.strip_prefix(pre) {
            s = r;
        }
    }
    let s = s.trim_end_matches(".dart");
    let s = s.replace(['$', ':'], "/").replace("//", "/");
    let s = s.trim_start_matches('/').to_string();
    s
}

/// 单个模式串是否命中名字：精确 → 忽略大小写精确 → （fuzzy）子串。
pub fn name_hit(pat: &str, hay: &str, fuzzy: bool) -> bool {
    let p = pat.trim();
    if p.is_empty() {
        return false;
    }
    if p == hay || norm_lib(p) == norm_lib(hay) {
        return true;
    }
    let (pl, hl) = (p.to_lowercase(), hay.to_lowercase());
    if pl == hl || norm_lib(&pl) == norm_lib(&hl) {
        return true;
    }
    if fuzzy {
        return hl.contains(&pl) || norm_lib(&hl).contains(&norm_lib(&pl));
    }
    false
}

/// 按 Selection 过滤 LibGroups；顺序与去重语义保持原样（只删不减）。
pub fn filter_libs(libs: &LibGroups, sel: &Selection) -> LibGroups {
    if sel.is_empty() {
        return libs.clone();
    }
    let mut out: LibGroups = Vec::new();
    for (lib, cls_map) in libs {
        if !sel.any_lib(lib) || sel.lib_excluded(lib) {
            continue;
        }
        let mut kept: Vec<(String, Vec<crate::analyzer::FuncEntry>)> = Vec::new();
        for (cls, funcs) in cls_map {
            if !sel.any_class(cls) {
                continue;
            }
            let f: Vec<crate::analyzer::FuncEntry> = funcs
                .iter()
                .filter(|e| sel.any_func(lib, cls, &e.mangled))
                .cloned()
                .collect();
            if !f.is_empty() {
                kept.push((cls.clone(), f));
            }
        }
        if !kept.is_empty() {
            out.push((lib.clone(), kept));
        }
    }
    out
}

/// 选中了多少个库 / 类 / 函数（用于给用户回显，避免"看起来什么都没发生"）
pub fn counts(libs: &LibGroups) -> (usize, usize, usize) {
    let l = libs.len();
    let c: usize = libs.iter().map(|(_, m)| m.len()).sum();
    let f: usize = libs
        .iter()
        .map(|(_, m)| m.iter().map(|(_, v)| v.len()).sum::<usize>())
        .sum();
    (l, c, f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lib_forms_are_equivalent() {
        let a = norm_lib("package:testing_app/screens/home.dart");
        let b = norm_lib("testing_app$screens$home");
        let c = norm_lib("testing_app/screens/home");
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(norm_lib("dart:core"), "core");
    }

    #[test]
    fn lib_prefix_selects_package() {
        let sel = Selection {
            libs: vec!["testing_app".into()],
            ..Default::default()
        };
        assert!(sel.any_lib("testing_app$screens$home"));
        assert!(sel.any_lib("package:testing_app/main.dart"));
        assert!(!sel.any_lib("package:flutter/src/widgets/framework.dart"));
    }

    #[test]
    fn exact_first_then_fuzzy() {
        assert!(name_hit("HomePage", "HomePage", false));
        assert!(name_hit("homepage", "HomePage", false)); // 大小写不敏感
        assert!(!name_hit("Home", "HomePage", false)); // 非模糊不子串
        assert!(name_hit("Home", "HomePage", true));
    }

    /// callers / callees / findrefs / text/call_edges.txt 输出的是**全点号**形式
    /// （`plan_functions` 造的），用户会把它抄回来喂给 disasm / getmethod / callers。
    /// 少这一种写法，下钻链就断在那里（实测断过：`dae disasm` 报 nothing matched）。
    #[test]
    fn func_hit_accepts_all_dots_form() {
        // SDK 库：内部名就是 `dart_core`（library_name 把 `dart:core` 写成 `dart_core`），
        // 与 findrefs 打出来的完全一致
        let sel = Selection {
            funcs: vec!["dart_core.RangeError.checkValidRange".to_string()],
            ..Default::default()
        };
        assert!(sel.any_func("dart_core", "RangeError", "checkValidRange"));
        // 包库：内部名用 `$` 分隔，规范化后用 `/`——两种写法都要认
        let sel2 = Selection {
            funcs: vec!["testing_app$screens$home.HomePage.build".to_string()],
            ..Default::default()
        };
        assert!(sel2.any_func("testing_app$screens$home", "HomePage", "build"));
        let sel3 = Selection {
            funcs: vec!["testing_app/screens/home.HomePage.build".to_string()],
            ..Default::default()
        };
        assert!(sel3.any_func("testing_app$screens$home", "HomePage", "build"));
        // 不该误命中别的类
        assert!(!sel.any_func("dart_core", "ArgumentError", "checkValidRange"));
    }

    #[test]
    fn func_hit_forms() {
        let sel = Selection {
            funcs: vec!["HomePage.build".into()],
            ..Default::default()
        };
        assert!(sel.any_func("testing_app$screens$home", "HomePage", "build"));
        assert!(!sel.any_func("testing_app$screens$home", "HomePage", "other"));
        let sel = Selection {
            funcs: vec!["build".into()],
            ..Default::default()
        };
        assert!(sel.any_func("x", "Y", "build"));
    }
}