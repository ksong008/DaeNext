mod native_object;

pub mod native_ebpf_build {
    use std::env;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    const RUST_NATIVE_BPF_OBJECT_ENV: &str = "DAE_RUST_NATIVE_BPF_OBJECT";
    const RUST_NATIVE_BPF_PNAME_CORE_OBJECT_ENV: &str = "DAE_RUST_NATIVE_BPF_PNAME_CORE_OBJECT";
    const RUST_NATIVE_BPF_PACKAGE: &str = "dae-ebpf-program";
    const RUST_NATIVE_BPF_OUTPUT: &str = "libdae_ebpf_program.so";
    const DEFAULT_NATIVE_BPF_OBJECT: &str = "dae-native-bpf_bpfel.o";
    const PNAME_CORE_NATIVE_BPF_OBJECT: &str = "dae-native-bpf-pname-core_bpfel.o";

    pub fn build_for_crate(crate_name: &str) {
        println!("cargo:rerun-if-changed=../dae-ebpf-program/Cargo.toml");
        println!("cargo:rerun-if-changed=../dae-ebpf-program/src");
        println!("cargo:rerun-if-changed=../dae-ebpf-abi/Cargo.toml");
        println!("cargo:rerun-if-changed=../dae-ebpf-abi/src");
        println!("cargo:rerun-if-changed=../../Cargo.toml");
        // Conservative dependency watch: the workspace lockfile pins every
        // dependency version (including build-std) used to produce the native
        // eBPF object, so a lockfile change must trigger a rebuild even when
        // no manifest or source file changed.
        println!("cargo:rerun-if-changed=../../Cargo.lock");
        println!("cargo:rerun-if-changed=../../.cargo/config.toml");
        println!("cargo:rerun-if-env-changed=DAE_RUST_NATIVE_BPF_CARGO");
        println!("cargo:rerun-if-env-changed=DAE_RUST_NATIVE_BPF_TOOLCHAIN");
        println!("cargo:rerun-if-env-changed=DAE_RUST_NATIVE_BPF_STRIP");
        println!("cargo:rerun-if-env-changed={RUST_NATIVE_BPF_OBJECT_ENV}");
        println!("cargo:rerun-if-env-changed={RUST_NATIVE_BPF_PNAME_CORE_OBJECT_ENV}");

        if env::var_os("CARGO_FEATURE_NATIVE_EBPF").is_none() {
            return;
        }

        let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let repo_root = repo_root_from_manifest(&manifest_dir, crate_name);
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let output = out_dir.join(DEFAULT_NATIVE_BPF_OBJECT);
        if let Some(source) = rust_native_bpf_object_override() {
            copy_native_aya_object(&source, &output);
        } else {
            build_rust_native_aya_object(repo_root, &out_dir, &output, &[]);
        }
        crate::native_object::strip_debug_and_validate(&output)
            .unwrap_or_else(|err| panic!("{err}"));

        let pname_core_output = out_dir.join(PNAME_CORE_NATIVE_BPF_OBJECT);
        if let Some(source) = rust_native_bpf_pname_core_object_override() {
            copy_native_aya_object(&source, &pname_core_output);
        } else {
            build_rust_native_aya_object(repo_root, &out_dir, &pname_core_output, &["pname-core"]);
        }
        crate::native_object::strip_debug_and_validate(&pname_core_output)
            .unwrap_or_else(|err| panic!("{err}"));
    }

    fn repo_root_from_manifest<'a>(manifest_dir: &'a Path, crate_name: &str) -> &'a Path {
        manifest_dir
            .ancestors()
            .find(|candidate| {
                candidate.join("Cargo.toml").is_file()
                    && candidate
                        .join("crates")
                        .join(crate_name)
                        .join("Cargo.toml")
                        .is_file()
            })
            .unwrap_or_else(|| panic!("{crate_name} manifest must live under crates/{crate_name}"))
    }

    fn rust_native_bpf_object_override() -> Option<PathBuf> {
        env::var_os(RUST_NATIVE_BPF_OBJECT_ENV).map(PathBuf::from)
    }

    fn rust_native_bpf_pname_core_object_override() -> Option<PathBuf> {
        env::var_os(RUST_NATIVE_BPF_PNAME_CORE_OBJECT_ENV).map(PathBuf::from)
    }

    fn copy_native_aya_object(source: &Path, output: &Path) {
        println!("cargo:rerun-if-changed={}", source.display());
        if !source.is_file() {
            panic!(
                "{RUST_NATIVE_BPF_OBJECT_ENV} points to a missing native eBPF object: {}",
                source.display()
            );
        }
        std::fs::copy(source, output).unwrap_or_else(|err| {
            panic!(
                "failed to copy native eBPF object from {} to {}: {err}",
                source.display(),
                output.display()
            )
        });
    }

    fn build_rust_native_aya_object(
        repo_root: &Path,
        out_dir: &Path,
        output: &Path,
        features: &[&str],
    ) {
        let cargo = env::var("DAE_RUST_NATIVE_BPF_CARGO").ok();
        let toolchain =
            env::var("DAE_RUST_NATIVE_BPF_TOOLCHAIN").unwrap_or_else(|_| "nightly".to_owned());
        let target_dir = out_dir.join("native-ebpf-target");
        let mut command = match cargo {
            Some(cargo) => Command::new(cargo),
            None => {
                let mut command = Command::new("rustup");
                command.arg("run").arg(toolchain).arg("cargo");
                command
            }
        };
        command
            .current_dir(repo_root)
            .env("CARGO_TARGET_DIR", &target_dir)
            .env_remove("CARGO")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env_remove("RUSTC")
            .env_remove("RUSTC_WRAPPER")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .env_remove("RUSTDOC")
            .env_remove("RUSTFLAGS")
            .arg("build")
            .arg("-Z")
            .arg("build-std=core")
            .arg("--manifest-path")
            .arg(repo_root.join("Cargo.toml"))
            .arg("-p")
            .arg(RUST_NATIVE_BPF_PACKAGE)
            .arg("--target")
            .arg("bpfel-unknown-none")
            .arg("--release");
        if !features.is_empty() {
            command.arg("--features").arg(features.join(","));
        }
        let status = command
            .output()
            .unwrap_or_else(|err| panic!("failed to run cargo for Rust native eBPF object: {err}"));
        if !status.status.success() {
            panic!(
                "Rust native Aya eBPF object build failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
                status.status,
                String::from_utf8_lossy(&status.stdout),
                String::from_utf8_lossy(&status.stderr)
            );
        }
        let built = target_dir
            .join("bpfel-unknown-none")
            .join("release")
            .join(RUST_NATIVE_BPF_OUTPUT);
        std::fs::copy(&built, output).unwrap_or_else(|err| {
            panic!(
                "failed to copy Rust native eBPF object from {} to {}: {err}",
                built.display(),
                output.display()
            )
        });
    }
}
