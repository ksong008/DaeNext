#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
native_target_dir="${CARGO_TARGET_DIR:-target}"
native_toolchain="${DAE_RUST_NATIVE_BPF_TOOLCHAIN:-1.100.0}"
[[ "$native_target_dir" = /* ]] || native_target_dir="$PWD/$native_target_dir"
object="$native_target_dir/bpfel-unknown-none/release/libdae_ebpf_program.so"
for variant in default pname-core; do
    args=()
    [[ "$variant" == default ]] || args+=(--features pname-core)
    RUSTC_BOOTSTRAP=1 cargo "+$native_toolchain" build --locked -Z build-std=core -p dae-ebpf-program \
        --target bpfel-unknown-none --release "${args[@]}"
    DAE_TEST_NATIVE_BPF_OBJECT="$object" cargo test --locked -p dae-ebpf-support \
        --features aya-loader --lib real_native_bpf_objects_define_the_lpm_inner_abi -- --nocapture
done
RUSTC_BOOTSTRAP=1 cargo "+$native_toolchain" build --locked -Z build-std=core -p dae-ebpf-program \
    --target bpfel-unknown-none --release --no-default-features --features trace-program
