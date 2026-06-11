use super::*;
pub(super) fn run_trace_loader_contract() -> LoaderOutput {
    let gate = dae_ebpf_support::trace_core_sideload_gate_report();
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "name": "rust-aya-trace-loader-contract",
            "binary": "dae-aya-bpf-loader",
            "compiled_native_ebpf": cfg!(feature = "native-ebpf"),
            "scope": "Rust/Aya trace CO-RE side-load contract is retained for audit but temporarily disabled",
            "core_sideload_enabled": gate.enabled,
            "disabled_reason": gate.disabled_reason,
            "production_daemon_path": false,
            "kernel_ebpf_program_rewrite": false,
            "native_trace_pinning_ready": gate.native_trace_pinning_ready,
            "rust_core_relocation_required": gate.rust_core_relocation_required,
            "restore_gate": gate.restore_gate,
            "required_pins": {
                "maps": null,
                "programs": null
            },
            "audit_smokes": {
                "attach_ringbuf": "disabled"
            },
            "config_source": {
                "port": "host-order u16, converted to BPF big-endian tracing_cfg.port",
                "l4_proto": "kernel protocol number",
                "ip_version": "4 or 6",
                "ringbuf_size": "events map max_entries override"
            }
        })
    ))
}
