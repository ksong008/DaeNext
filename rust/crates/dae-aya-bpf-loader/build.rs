use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../../../control/kern/tproxy.c");
    println!("cargo:rerun-if-changed=../../../control/kern/headers");
    println!("cargo:rerun-if-env-changed=CLANG");
    println!("cargo:rerun-if-env-changed=MAX_MATCH_SET_LEN");

    if env::var_os("CARGO_FEATURE_NATIVE_EBPF").is_none() {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir
        .ancestors()
        .nth(3)
        .expect("dae-aya-bpf-loader manifest must live under rust/crates/dae-aya-bpf-loader");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let output = out_dir.join("dae-native-bpf_bpfel.o");
    compile_native_aya_object(repo_root, &output);
}

fn compile_native_aya_object(repo_root: &Path, output: &Path) {
    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".to_owned());
    let max_match_set_len = env::var("MAX_MATCH_SET_LEN").unwrap_or_else(|_| "1024".to_owned());
    let source = repo_root.join("control/kern/tproxy.c");
    let headers = repo_root.join("control/kern/headers");
    let status = Command::new(&clang)
        .arg("-g")
        .arg("-O2")
        .arg("-Wall")
        .arg("-Werror")
        .arg(format!("-DMAX_MATCH_SET_LEN={max_match_set_len}"))
        .arg("-DDAE_AYA_EBPF_OBJECT")
        .arg("-target")
        .arg("bpfel")
        .arg("-c")
        .arg(&source)
        .arg("-I")
        .arg(&headers)
        .arg("-o")
        .arg(output)
        .output()
        .unwrap_or_else(|err| panic!("failed to run {clang} for native Aya eBPF object: {err}"));
    if !status.status.success() {
        panic!(
            "native Aya eBPF object build failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            status.status,
            String::from_utf8_lossy(&status.stdout),
            String::from_utf8_lossy(&status.stderr)
        );
    }
}
