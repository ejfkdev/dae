fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags");
    println!("cargo:rerun-if-env-changed=DAE_VERSION");

    // 版本优先取 CI 触发时的 tag（DAE_VERSION = github.ref_name，如 v0.1.2）；
    // 本地构建恰好在某个 tag 上则用该 tag；否则回退 Cargo 包版本（补 v 前缀）。
    // 不再带 -N-gHASH 的 dev 后缀，保证二进制内嵌版本与发布 tag 一致。
    let ver = std::env::var("DAE_VERSION")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::process::Command::new("git")
                .args(["describe", "--tags", "--exact-match"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| {
            format!(
                "v{}",
                std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.1.0".into())
            )
        });
    println!("cargo:rustc-env=GIT_VERSION={ver}");
}