include!("../../build/native_ebpf_build.rs");

fn main() {
    emit_product_build_identity();
    native_ebpf_build::build_for_crate("dae-daemon");
}

fn emit_product_build_identity() {
    use std::env;
    use std::path::Path;

    println!("cargo:rerun-if-env-changed=DAE_DAEMON_VERSION");
    if let Some(version) = env::var("DAE_DAEMON_VERSION")
        .ok()
        .and_then(|value| sanitize_identity(value))
    {
        println!("cargo:rustc-env=DAE_DAEMON_VERSION={version}");
        return;
    }

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_dir = Path::new(&manifest_dir);
    let repo_root = manifest_dir
        .ancestors()
        .find(|candidate| {
            candidate.join("Cargo.toml").is_file()
                && candidate
                    .join("crates")
                    .join("dae-daemon")
                    .join("Cargo.toml")
                    .is_file()
        })
        .unwrap_or_else(|| panic!("dae-daemon manifest must live under crates/dae-daemon"));
    let package_version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_owned());
    let commit = git_output(repo_root, &["rev-parse", "--short=12", "HEAD"])
        .unwrap_or_else(|| "unknown".to_owned());
    let dirty = if git_dirty(repo_root) { "+dirty" } else { "" };
    let profile = env::var("PROFILE").unwrap_or_else(|_| "unknown".to_owned());
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned());
    let features = enabled_feature_summary();
    let version = format!(
        "daed rust-native product {package_version} dae-core={commit}{dirty} profile={profile} target={target} features={features}"
    );
    println!("cargo:rustc-env=DAE_DAEMON_VERSION={version}");
}

fn enabled_feature_summary() -> String {
    [
        ("native-ebpf", "CARGO_FEATURE_NATIVE_EBPF"),
        ("jemalloc", "CARGO_FEATURE_ALLOCATOR_JEMALLOC"),
        ("system-allocator", "CARGO_FEATURE_ALLOCATOR_SYSTEM"),
    ]
    .into_iter()
    .filter_map(|(name, env_name)| std::env::var_os(env_name).map(|_| name))
    .collect::<Vec<_>>()
    .join(",")
}

fn git_output(repo_root: &std::path::Path, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    sanitize_identity(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn git_dirty(repo_root: &std::path::Path) -> bool {
    std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| !output.stdout.is_empty())
        .unwrap_or(false)
}

fn sanitize_identity(value: String) -> Option<String> {
    let sanitized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    (!sanitized.is_empty()).then_some(sanitized)
}
