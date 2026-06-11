use crate::*;

#[test]
fn trace_event_abi_contract_matches_c_ringbuf_record_shape() {
    let abi = trace_event_abi_contract();
    assert_eq!(abi.addr_size, 16);
    assert_eq!(abi.ifname_len, 16);
    assert_eq!(abi.pname_len, 32);
    assert_eq!(abi.meta_size, 88);
    assert_eq!(abi.tuple_size, 42);
    assert_eq!(abi.event_size, 130);
    assert_eq!(abi.tracing_config_size, 6);
    assert_eq!(abi.skb_addresses_max_entries, 1024);
    assert_eq!(abi.events_external_compat_bytes, 1 << 29);
    assert_eq!(abi.events_native_runtime_bytes, 64 << 20);
    assert_eq!(abi.max_tracked_skbs, 4096);
    assert_eq!(abi.max_events_per_skb, 64);
    assert_eq!(abi.max_symbols_per_skb, 64);
}

#[test]
fn trace_config_rewrite_contract_keeps_trace_endian_and_ringbuf_semantics() {
    let rewrite = trace_config_rewrite_contract();
    assert!(rewrite.port_is_network_order);
    assert!(rewrite.l4_proto_is_host_order);
    assert!(rewrite.ip_version_is_u8);
    assert!(rewrite.explicit_padding_byte);
    assert!(rewrite.ringbuf_size_runtime_override);
}

#[test]
fn trace_kprobe_contract_covers_skb_argument_positions_and_lifetime_cleanup() {
    let programs = trace_kprobe_program_specs();
    assert_eq!(programs.len(), 6);
    for position in 1..=5 {
        assert!(programs.iter().any(|program| {
            program.section == format!("kprobe/skb-{position}").as_str()
                && program.program_name == format!("kprobe_skb_{position}").as_str()
                && program.skb_arg_position == Some(position)
                && !program.lifetime_termination
        }));
    }
    assert!(programs.iter().any(|program| {
        program.section == "kprobe/skb_lifetime_termination"
            && program.program_name == "kprobe_skb_lifetime_termination"
            && program.skb_arg_position == Some(1)
            && program.lifetime_termination
    }));

    let discovery = trace_target_discovery_contract();
    assert!(discovery.feature_gated);
    assert_eq!(discovery.build_tag, "trace");
    assert!(discovery.uses_kernel_btf);
    assert_eq!(discovery.max_skb_arg_position, 5);
    assert_eq!(discovery.lifetime_termination_target, "kfree_skbmem");
    assert!(discovery.requires_bpf_get_func_ip);
    assert!(discovery.event_consumer_symbolizes_pc);
}

#[test]
fn trace_kprobe_evidence_queue_keeps_native_trace_missing_until_real_skb_core_read() {
    let evidence = trace_kprobe_evidence_queue();
    assert_eq!(evidence.len(), 7);
    assert!(evidence.iter().all(|line| {
        line.check == KernelProgramParityCheck::TraceKprobeCoverage
            && !line.required_before_production_admission
    }));
    assert!(evidence.iter().any(|line| {
        line.item == "trace_event_ringbuf_record_abi"
            && line.status == KernelProgramParityEvidenceStatus::Passed
    }));
    assert!(evidence.iter().any(|line| {
        line.item == "btf_skb_target_discovery_contract"
            && line.status == KernelProgramParityEvidenceStatus::Passed
    }));
    assert!(evidence.iter().any(|line| {
        line.item == "rust_skb_core_read_semantics"
            && line.status == KernelProgramParityEvidenceStatus::Missing
    }));
    assert!(evidence.iter().any(|line| {
        line.item == "rust_trace_load_pin_smoke"
            && line.status == KernelProgramParityEvidenceStatus::Passed
    }));
    assert!(evidence.iter().any(|line| {
        line.item == "rust_trace_attach_and_ringbuf_smoke"
            && line.status == KernelProgramParityEvidenceStatus::Passed
    }));
    assert!(!trace_kprobe_evidence_admitted());
}

#[test]
fn trace_core_sideload_gate_is_disabled_until_real_core_relocations_exist() {
    let gate = trace_core_sideload_gate_report();
    assert_eq!(gate.schema, "trace-core-sideload-gate");
    assert!(!gate.enabled);
    assert!(!gate.native_trace_pinning_ready);
    assert!(!gate.production_daemon_path);
    assert!(gate.rust_skb_core_read_semantics_required);
    assert!(gate.rust_core_relocation_required);
    assert!(!gate.external_ebpf_trace_object_required);
    assert!(!gate.external_trace_dependency_required);
    assert!(
        gate.disabled_reason
            .contains("excluded from the production runtime path")
    );
    assert!(gate.restore_gate.contains("core_relo_len"));
}
