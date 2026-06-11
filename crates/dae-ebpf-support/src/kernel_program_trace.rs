use crate::kernel_program::{
    KernelProgramParityCheck, KernelProgramParityEvidenceLine, KernelProgramParityEvidenceStatus,
};

pub const TRACE_CORE_SIDELOAD_DISABLED_REASON: &str = "trace diagnostic is excluded from the production runtime path; Rust/Aya CO-RE side-load remains disabled until real sk_buff CO-RE relocation parity is proven";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceEventAbiContract {
    pub addr_size: usize,
    pub ifname_len: usize,
    pub pname_len: usize,
    pub meta_size: usize,
    pub tuple_size: usize,
    pub event_size: usize,
    pub tracing_config_size: usize,
    pub skb_addresses_max_entries: u32,
    pub events_external_compat_bytes: u32,
    pub events_native_runtime_bytes: u32,
    pub max_tracked_skbs: usize,
    pub max_events_per_skb: usize,
    pub max_symbols_per_skb: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceConfigRewriteContract {
    pub port_is_network_order: bool,
    pub l4_proto_is_host_order: bool,
    pub ip_version_is_u8: bool,
    pub explicit_padding_byte: bool,
    pub ringbuf_size_runtime_override: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceKprobeProgramSpec {
    pub section: &'static str,
    pub program_name: &'static str,
    pub skb_arg_position: Option<u8>,
    pub lifetime_termination: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceTargetDiscoveryContract {
    pub feature_gated: bool,
    pub build_tag: &'static str,
    pub uses_kernel_btf: bool,
    pub max_skb_arg_position: u8,
    pub lifetime_termination_target: &'static str,
    pub requires_bpf_get_func_ip: bool,
    pub event_consumer_symbolizes_pc: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceCoreSideloadGateReport {
    pub schema: &'static str,
    pub enabled: bool,
    pub native_trace_pinning_ready: bool,
    pub production_daemon_path: bool,
    pub rust_skb_core_read_semantics_required: bool,
    pub rust_core_relocation_required: bool,
    pub external_ebpf_trace_object_required: bool,
    pub external_trace_dependency_required: bool,
    pub disabled_reason: &'static str,
    pub restore_gate: &'static str,
}

pub fn trace_event_abi_contract() -> TraceEventAbiContract {
    TraceEventAbiContract {
        addr_size: 16,
        ifname_len: 16,
        pname_len: 32,
        meta_size: 88,
        tuple_size: 42,
        event_size: 130,
        tracing_config_size: 6,
        skb_addresses_max_entries: 1024,
        events_external_compat_bytes: 1 << 29,
        events_native_runtime_bytes: 64 << 20,
        max_tracked_skbs: 4096,
        max_events_per_skb: 64,
        max_symbols_per_skb: 64,
    }
}

pub fn trace_config_rewrite_contract() -> TraceConfigRewriteContract {
    TraceConfigRewriteContract {
        port_is_network_order: true,
        l4_proto_is_host_order: true,
        ip_version_is_u8: true,
        explicit_padding_byte: true,
        ringbuf_size_runtime_override: true,
    }
}

pub fn trace_kprobe_program_specs() -> Vec<TraceKprobeProgramSpec> {
    vec![
        trace_skb_arg_program("kprobe/skb-1", "kprobe_skb_1", 1),
        trace_skb_arg_program("kprobe/skb-2", "kprobe_skb_2", 2),
        trace_skb_arg_program("kprobe/skb-3", "kprobe_skb_3", 3),
        trace_skb_arg_program("kprobe/skb-4", "kprobe_skb_4", 4),
        trace_skb_arg_program("kprobe/skb-5", "kprobe_skb_5", 5),
        TraceKprobeProgramSpec {
            section: "kprobe/skb_lifetime_termination",
            program_name: "kprobe_skb_lifetime_termination",
            skb_arg_position: Some(1),
            lifetime_termination: true,
        },
    ]
}

pub fn trace_target_discovery_contract() -> TraceTargetDiscoveryContract {
    TraceTargetDiscoveryContract {
        feature_gated: true,
        build_tag: "trace",
        uses_kernel_btf: true,
        max_skb_arg_position: 5,
        lifetime_termination_target: "kfree_skbmem",
        requires_bpf_get_func_ip: true,
        event_consumer_symbolizes_pc: true,
    }
}

pub fn trace_core_sideload_gate_report() -> TraceCoreSideloadGateReport {
    TraceCoreSideloadGateReport {
        schema: "trace-core-sideload-gate",
        enabled: false,
        native_trace_pinning_ready: false,
        production_daemon_path: false,
        rust_skb_core_read_semantics_required: true,
        rust_core_relocation_required: true,
        external_ebpf_trace_object_required: false,
        external_trace_dependency_required: false,
        disabled_reason: TRACE_CORE_SIDELOAD_DISABLED_REASON,
        restore_gate: "trace diagnostic is excluded from production runtime; enabling it requires nonzero Rust .BTF.ext core_relo_len, verifier load, and semantic ringbuf parity",
    }
}

pub fn trace_kprobe_evidence_queue() -> Vec<KernelProgramParityEvidenceLine> {
    vec![
        trace_evidence_line(
            "trace_event_ringbuf_record_abi",
            KernelProgramParityEvidenceStatus::Passed,
            "crates/dae-ebpf-program/src/trace.rs",
        ),
        trace_evidence_line(
            "tracing_cfg_rewrite_contract",
            KernelProgramParityEvidenceStatus::Passed,
            "dae-ebpf-support::AyaTraceConfig",
        ),
        trace_evidence_line(
            "events_ringbuf_and_skb_addresses_maps",
            KernelProgramParityEvidenceStatus::Passed,
            "crates/dae-ebpf-program/src/trace.rs",
        ),
        trace_evidence_line(
            "btf_skb_target_discovery_contract",
            KernelProgramParityEvidenceStatus::Passed,
            "dae-ebpf-support::TraceTargetDiscoveryContract",
        ),
        trace_evidence_line(
            "rust_skb_core_read_semantics",
            KernelProgramParityEvidenceStatus::Missing,
            "crates/dae-ebpf-program/src/trace.rs",
        ),
        trace_evidence_line(
            "rust_trace_load_pin_smoke",
            KernelProgramParityEvidenceStatus::Passed,
            "trace load-pin smoke evidence; CO-RE side-load remains disabled",
        ),
        trace_evidence_line(
            "rust_trace_attach_and_ringbuf_smoke",
            KernelProgramParityEvidenceStatus::Passed,
            "trace attach-ringbuf smoke evidence; CO-RE side-load remains disabled",
        ),
    ]
}

pub fn trace_kprobe_evidence_admitted() -> bool {
    trace_kprobe_evidence_queue()
        .iter()
        .all(|line| line.status == KernelProgramParityEvidenceStatus::Passed)
}

const fn trace_skb_arg_program(
    section: &'static str,
    program_name: &'static str,
    skb_arg_position: u8,
) -> TraceKprobeProgramSpec {
    TraceKprobeProgramSpec {
        section,
        program_name,
        skb_arg_position: Some(skb_arg_position),
        lifetime_termination: false,
    }
}

const fn trace_evidence_line(
    item: &'static str,
    status: KernelProgramParityEvidenceStatus,
    source: &'static str,
) -> KernelProgramParityEvidenceLine {
    KernelProgramParityEvidenceLine {
        check: KernelProgramParityCheck::TraceKprobeCoverage,
        item,
        status,
        source,
        required_before_production_admission: false,
    }
}
