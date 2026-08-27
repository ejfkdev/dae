fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags");
    println!("cargo:rerun-if-env-changed=DAE_VERSION");

    // CI 由 tag 触发构建时显式传入 DAE_VERSION（= github.ref_name），
    // 保证二进制内嵌版本与 GitHub tag 一致；本地构建回退 git describe，
    // 再回退 Cargo 包版本。
    let ver = std::env::var("DAE_VERSION")
        .ok()
        .or_else(|| {
            std::process::Command::new("git")
                .args(["describe", "--tags", "--always", "--dirty"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.1.0".into()));
    println!("cargo:rustc-env=GIT_VERSION={ver}");
}