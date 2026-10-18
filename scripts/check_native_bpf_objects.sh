#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
object="${CARGO_TARGET_DIR:-target}/bpfel-unknown-none/release/libdae_ebpf_program.so"
for variant in default pname-core; do
    args=()
    [[ "$variant" == default ]] || args+=(--features pname-core)
    cargo +nightly build --locked -Z build-std=core -p dae-ebpf-program \
        --target bpfel-unknown-none --release "${args[@]}"
    DAE_TEST_NATIVE_BPF_OBJECT="$object" cargo test --locked -p dae-ebpf-support \
        --features aya-loader --lib real_native_bpf_objects_define_the_lpm_inner_abi -- --nocapture
done
cargo +nightly build --locked -Z build-std=core -p dae-ebpf-program \
    --target bpfel-unknown-none --release --no-default-features --features trace-program
