//! CLI 文案双语（zh/en）与语言探测。
//!
//! 探测优先级：`DAE_LANG`（显式 zh/en）→ `LC_ALL` → `LC_MESSAGES` → `LANG`。
//! 中文语系（简体/繁体，如 `zh_CN`、`zh_TW`、`zh_Hant`）→ 中文；其余一律英文。
//! `C`/`POSIX` 与空值视为未设置。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Zh,
    En,
}

impl Lang {
    pub fn pick(self, zh: &'static str, en: &'static str) -> &'static str {
        match self {
            Lang::Zh => zh,
            Lang::En => en,
        }
    }
}

fn lang_tag(value: &str) -> String {
    // "zh_CN.UTF-8" → "zh_cn"；"C" → "c"
    value
        .split('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn match_lang(tag: &str) -> Option<Lang> {
    if tag.is_empty() || tag == "c" || tag == "posix" {
        return None; // 未设置
    }
    if tag.starts_with("zh") {
        return Some(Lang::Zh); // 简体/繁体均中文
    }
    Some(Lang::En)
}

pub fn detect() -> Lang {
    if let Ok(v) = std::env::var("DAE_LANG") {
        let tag = lang_tag(&v);
        if !tag.is_empty() {
            return match_lang(&tag).unwrap_or(Lang::En);
        }
    }
    for key in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(v) = std::env::var(key) {
            if let Some(l) = match_lang(&lang_tag(&v)) {
                return l;
            }
        }
    }
    Lang::En
}

/// main.rs / detect.rs 的用户可见文案（zh, en 成对，随启动时的语言探测定稿）
pub struct Messages {
    pub lang: Lang,
    pub target_label: &'static str,
    pub err_prefix: &'static str,
    pub warn_prefix: &'static str,
    pub err_sdk_arg: &'static str,
    pub err_platform_arg: &'static str,
    pub err_read_binary: &'static str,
    pub err_read_sdk: &'static str,
    pub err_read_platform: &'static str,
    pub err_bare_jit: &'static str,
    pub err_container: &'static str,
    pub err_platform_missing: &'static str,
    pub err_flutter_dir: &'static str,
    pub sdk_profile_label: &'static str,
    pub detect_basis_hash: &'static str,
    pub detect_basis_probe: &'static str,
    pub detect_basis_low: &'static str,
    pub detect_fallback: &'static str,
    pub sdk_unverified: &'static str,
    pub export_done: &'static str,
    pub sum_r2: &'static str,
    pub sum_ida: &'static str,
    pub sum_frida: &'static str,
    pub sum_asm: &'static str,
    pub sum_pp: &'static str,
    pub sum_objs: &'static str,
}

pub fn messages(lang: Lang) -> Messages {
    let p = |zh: &'static str, en: &'static str| lang.pick(zh, en);
    Messages {
        lang,
        target_label: p("目标", "target"),
        err_prefix: p("错误", "error"),
        warn_prefix: p("警告", "warning"),
        err_sdk_arg: p("错误: --sdk-profile 缺少参数", "error: --sdk-profile requires an argument"),
        err_platform_arg: p(
            "错误: --platform-profile 缺少参数",
            "error: --platform-profile requires an argument",
        ),
        err_read_binary: p("读二进制失败", "failed to read binary"),
        err_read_sdk: p("读 --sdk-profile: ", "reading --sdk-profile: "),
        err_read_platform: p("读 --platform-profile: ", "reading --platform-profile: "),
        err_bare_jit: p(
            "裸 app-JIT 快照（kMessageMagic）没有容器包裹，暂不支持（需 AOT 产物：dart compile aot-snapshot / dart2native / Flutter release 构建）",
            "bare app-JIT snapshot (kMessageMagic) has no container wrapper and is unsupported (an AOT artifact is required: dart compile aot-snapshot / dart2native / Flutter release build)",
        ),
        err_container: p(
            "无法识别容器格式（不是 Mach-O/ELF/PE）",
            "unrecognized container format (not Mach-O/ELF/PE)",
        ),
        err_platform_missing: p(
            "暂无内嵌平台 Profile，请用 --platform-profile 指定（在 profiles/platform/ 下新建一份即可）",
            "no embedded platform profile; use --platform-profile (create one under profiles/platform/)",
        ),
        err_flutter_dir: p("目录内未找到 Flutter 二进制（尝试了", "no Flutter binary found inside directory (tried"),
        sdk_profile_label: p("SDK Profile", "SDK profile"),
        detect_basis_hash: p("版本指纹命中", "version-hash match"),
        detect_basis_probe: p("结构推断", "structural probe"),
        detect_basis_low: p("结构推断·低置信", "structural probe, low confidence"),
        detect_fallback: p(
            "警告: 无法自动识别 Dart 版本，回退内嵌 dart/3.3.4（可用 --sdk-profile 显式指定）",
            "warning: cannot auto-detect the Dart version; falling back to embedded dart/3.3.4 (override with --sdk-profile)",
        ),
        sdk_unverified: p(
            "状态为 unverified（该版本的样本对拍尚未全部完成）。导出结果仅供参考，请以 verified 版本结果为准",
            "is unverified (sample comparison for this version is incomplete); exports are indicative — prefer verified versions",
        ),
        export_done: p("导出完成 →", "export done ->"),
        sum_r2: p("条函数名/地址", "named functions/addresses"),
        sum_ida: p("个函数命名 + Dart 结构头", "named functions + Dart struct header"),
        sum_frida: p("个 Classes 条目", "Classes entries"),
        sum_asm: p("个函数反汇编 + IL", "disassembled functions + IL"),
        sum_pp: p("个对象池条目", "object pool entries"),
        sum_objs: p("个用户类实例", "user class instances"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zh_variants_pick_chinese() {
        for tag in ["zh_cn", "zh-cn", "zh_cn.utf-8", "zh_tw", "zh_hant", "zh"] {
            assert_eq!(match_lang(&lang_tag(tag)), Some(Lang::Zh), "tag={tag}");
        }
    }

    #[test]
    fn non_zh_picks_english() {
        for tag in ["en_us.utf-8", "de_DE", "ja_JP", "fr_FR.UTF-8"] {
            assert_eq!(match_lang(&lang_tag(tag)), Some(Lang::En), "tag={tag}");
        }
    }

    #[test]
    fn c_posix_empty_are_unset() {
        assert_eq!(match_lang(&lang_tag("C.UTF-8")), None);
        assert_eq!(match_lang(&lang_tag("POSIX")), None);
        assert_eq!(match_lang(&lang_tag("")), None);
    }
}
