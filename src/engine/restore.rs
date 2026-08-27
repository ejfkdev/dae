//! 命名还原（纯字符串变换，跨版本稳定）：library_name / scrub_name / mangle，
//! 与 blutter（及参考实现 dart_aot_full.py）逐字符一致。

use std::collections::HashMap;

/// DartLibrary::GetName() 的 mangling
pub fn library_name(url: &str) -> String {
    let mut out = url.to_string();
    if url.starts_with("package:") {
        out = url[8..].to_string();
    } else if url.starts_with("file:") {
        // 取倒数第二个 '/' 之后的段
        if let Some(i) = url.rfind('/') {
            if let Some(j) = url[..i].rfind('/') {
                out = url[j + 1..].to_string();
            } else {
                out = url[i + 1..].to_string();
            }
        }
    } else if url.starts_with("dart:") {
        out = format!("dart_{}", &url[5..]);
    }
    if let Some(stripped) = out.strip_suffix(".dart") {
        out = stripped.to_string();
    }
    out.replace('/', "$")
}

/// String::ScrubName（UserVisibleName）。
/// 注意：按字符（非字节）处理，与 Python str 语义一致。
pub fn scrub_name(name: Option<&str>) -> String {
    let name = match name {
        None => return String::new(),
        Some(n) => n,
    };
    if name == "::" {
        return String::new();
    }
    let chars: Vec<char> = name.chars().collect();
    // 1. 去掉 @<digits>
    let mut out: Vec<char> = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '@' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit() {
            i += 1;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    let s: Vec<char> = out;
    if s.is_empty() {
        return String::new();
    }
    // 2. 处理 ":"（get:/set:/dyn: 前缀）。只允许一个 ':'。
    let mut start = 0usize;
    let mut is_setter = false;
    let mut dot_pos: i64 = -1;
    for (i, &ch) in s.iter().enumerate() {
        if ch == ':' {
            if start != 0 {
                start = 0;
                dot_pos = -1;
                break;
            }
            if s[0] == 's' {
                is_setter = true;
            }
            start = i + 1;
        } else if ch == '.' {
            if dot_pos != -1 {
                start = 0;
                dot_pos = -1;
                break;
            }
            dot_pos = i as i64;
        }
    }
    if start == 0 && dot_pos == -1 {
        return s.into_iter().collect();
    }
    // dot_pos == -1 时取 len（Python 里 -1 + 1 == len(s) 恒不成立，因为 s 非空）
    let end = if dot_pos >= 0 && dot_pos + 1 == s.len() as i64 {
        dot_pos as usize
    } else {
        s.len()
    };
    let mut substr: String = s[start..end].iter().collect();
    if is_setter {
        substr.push('=');
    }
    substr
}

pub fn op_map() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    for (k, v) in [
        ("==", "eq"), ("<", "lt"), (">", "gt"), ("<=", "lte"), (">=", "gte"),
        ("=", "assign"), ("[]", "at"), ("[]=", "at_assign"), ("++", "increment"),
        ("--", "decrement"), ("+", "add"), ("-", "sub"), ("*", "mul"), ("~/", "div"),
        ("/", "divf"), ("%", "mod"), ("&", "LAnd"), ("|", "LOr"), ("^", "xor"),
        ("~", "not"), (">>", "shar"), ("<<", "shal"),
    ] {
        m.insert(k, v);
    }
    m
}

/// blutter DartFunction::Kind 映射。kind = kind_tag & 0x1F
pub fn func_blutter_kind(kind: i64) -> &'static str {
    match kind {
        5 => "CONSTRUCTOR",
        4 | 7 => "SETTER",
        3 | 6 | 8 => "GETTER",
        _ => "NORMAL",
    }
}

pub fn func_kind_aot_name(kind: i64) -> String {
    match kind {
        0 => "RegularFunction",
        1 => "ClosureFunction",
        2 => "ImplicitClosureFunction",
        3 => "GetterFunction",
        4 => "SetterFunction",
        5 => "Constructor",
        6 => "ImplicitGetter",
        7 => "ImplicitSetter",
        8 => "ImplicitStaticGetter",
        9 => "FieldInitializer",
        10 => "MethodExtractor",
        11 => "NoSuchMethodDispatcher",
        12 => "InvokeFieldDispatcher",
        13 => "IrregexpFunction",
        14 => "DynamicInvocationForwarder",
        15 => "FfiTrampoline",
        16 => "RecordFieldGetter",
        _ => "UnknownKind",
    }
    .to_string()
}

/// blutter getFunctionName4Ida 的 mangling。fn_name 已是 UserVisibleName。
pub fn get_function_name_4_ida(
    fn_name: &str,
    cls_prefix: &str,
    kind: &str,
    vm_kind: i64,
    is_static: bool,
) -> String {
    if vm_kind == 1 && fn_name == "<anonymous closure>" {
        return "_anon_closure".to_string();
    }
    let mut fn_name = fn_name.to_string();
    if fn_name.starts_with('#') {
        fn_name = format!("@{}", &fn_name[1..]);
    }
    // 过滤 # 非法字符序列（'@#', '0#', '#'）
    let chars: Vec<char> = fn_name.chars().collect();
    let mut out: Vec<char> = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '@' && i + 1 < chars.len() && chars[i + 1] == '#' {
            out.push('_');
            i += 2;
        } else if chars[i] == '0' && i + 1 < chars.len() && chars[i + 1] == '#' {
            out.push('0');
            i += 2;
        } else if chars[i] == '#' {
            out.push('_');
            i += 1;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    let fn_name: String = out.into_iter().collect();

    let ops = op_map();
    if let Some(v) = ops.get(fn_name.as_str()) {
        return format!("op_{v}");
    }
    if let Some(stripped) = fn_name.strip_suffix('=') {
        return format!("{stripped}_assign");
    }
    if let Some(stripped) = fn_name.strip_suffix('-') {
        return format!("{stripped}_neg");
    }
    if let Some(stripped) = fn_name.strip_suffix('!') {
        return format!("{stripped}_not");
    }
    if kind == "CONSTRUCTOR" {
        let mut name = if is_static { "factory_ctor" } else { "ctor" }.to_string();
        if let Some(rest) = fn_name.strip_prefix(cls_prefix) {
            if let Some(r1) = rest.strip_prefix('.') {
                name = format!("{name}_{r1}");
            }
        }
        return name;
    }
    if kind == "SETTER" {
        return format!("set_{fn_name}");
    }
    if kind == "GETTER" {
        return format!("get_{fn_name}");
    }
    fn_name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_privkey() {
        assert_eq!(scrub_name(Some("foo@123456")), "foo");
    }

    #[test]
    fn scrub_getter() {
        assert_eq!(scrub_name(Some("get:field")), "field");
    }

    #[test]
    fn scrub_dyn_getter() {
        assert_eq!(scrub_name(Some("dyn:get:field")), "dyn:get:field");
    }

    #[test]
    fn scrub_setter() {
        assert_eq!(scrub_name(Some("set:field")) , "field=");
    }

    #[test]
    fn scrub_top_level() {
        assert_eq!(scrub_name(Some("::")), "");
    }

    #[test]
    fn lib_package() {
        assert_eq!(library_name("package:x/an.dart"), "x$an");
    }

    #[test]
    fn lib_dart() {
        assert_eq!(library_name("dart:core"), "dart_core");
    }

    #[test]
    fn mangle_closure() {
        assert_eq!(get_function_name_4_ida("<anonymous closure>", "", "NORMAL", 1, false), "_anon_closure");
    }

    #[test]
    fn mangle_op() {
        assert_eq!(get_function_name_4_ida("==", "", "NORMAL", 0, false), "op_eq");
    }

    #[test]
    fn mangle_ctor() {
        assert_eq!(get_function_name_4_ida("Foo.bar", "Foo", "CONSTRUCTOR", 5, false), "ctor_bar");
        assert_eq!(get_function_name_4_ida("Foo.bar", "Foo", "CONSTRUCTOR", 5, true), "factory_ctor_bar");
    }
}