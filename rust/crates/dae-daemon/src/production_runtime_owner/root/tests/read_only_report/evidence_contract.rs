use super::*;
pub(super) fn assert_kernel_evidence_and_contract(report: &serde_json::Value) {
    let kernel_program_evidence =
        report["ebpf_backend_capabilities"]["kernel_program_parity_admission"]["evidence_queue"]
            .as_array()
            .unwrap();
    assert!(kernel_program_evidence.iter().any(|entry| {
        entry["check"].as_str().unwrap() == "packet_level_golden_parity"
            && entry["item"].as_str().unwrap() == "l2_ipv4_tcp"
            && entry["status"].as_str().unwrap() == "passed"
    }));
    assert!(kernel_program_evidence.iter().any(|entry| {
        entry["check"].as_str().unwrap() == "map_abi_btf_verifier_parity"
            && entry["item"].as_str().unwrap() == "abi_layout_golden_fixture"
            && entry["status"].as_str().unwrap() == "passed"
    }));
    assert!(kernel_program_evidence.iter().any(|entry| {
        entry["check"].as_str().unwrap() == "map_abi_btf_verifier_parity"
            && entry["item"].as_str().unwrap() == "rust_object_btf_timer_verifier_admission"
            && entry["status"].as_str().unwrap() == "passed"
    }));
    assert!(kernel_program_evidence.iter().any(|entry| {
        entry["check"].as_str().unwrap() == "map_abi_btf_verifier_parity"
            && entry["item"].as_str().unwrap() == "c_vs_rust_object_map_catalog_diff"
            && entry["status"].as_str().unwrap() == "passed"
    }));
    assert!(kernel_program_evidence.iter().any(|entry| {
        entry["check"].as_str().unwrap() == "matched_go_rust_benchmark"
            && entry["item"].as_str().unwrap()
                == "count10_same_corpus_default_daemon_ready_benchmark"
            && entry["status"].as_str().unwrap() == "passed"
    }));
    assert_eq!(
        report["contract"]["ebpf_backend"]["selected_backend"]
            .as_str()
            .unwrap(),
        "tc_command_fallback"
    );
    assert!(
        report["go_bpf_loader_retirement_candidate"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["go_bpf_fallback_retirement_gate_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        report["go_bpf_fallback_retirement_scope"].as_str().unwrap(),
        "kernel-facing-tproxy-default-rust-aya; trace diagnostic retired from product default; outbound protocol boundary preserved"
    );
    assert!(report["go_bpf_fallback_required"].as_bool().unwrap());
    assert!(!report["go_bpf_fallback_retired"].as_bool().unwrap());
    assert!(
        report["ebpf_backend_capabilities"]["cgroup_attach"]["go_attachcgroup_fallback_retired"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
}
