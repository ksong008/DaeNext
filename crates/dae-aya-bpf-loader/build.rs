include!("../../build/native_ebpf_build.rs");

fn main() {
    native_ebpf_build::build_for_crate("dae-aya-bpf-loader");
}
