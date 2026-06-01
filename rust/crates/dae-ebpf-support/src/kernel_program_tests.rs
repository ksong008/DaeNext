use crate::*;

#[test]
fn kernel_program_feasibility_keeps_a4_as_evaluation_not_default_switch() {
    let report = kernel_program_feasibility_report();
    assert_eq!(report.schema, "kernel-program-feasibility-v1");
    assert_eq!(report.tproxy_classifier_total, 10);
    assert_eq!(report.rust_tproxy_classifier_covered, 10);
    assert_eq!(report.tproxy_cgroup_total, 6);
    assert_eq!(report.rust_tproxy_cgroup_covered, 6);
    assert_eq!(report.trace_kprobe_total, 6);
    assert_eq!(report.rust_trace_kprobe_covered, 0);
    assert!(report.rust_tproxy_runtime_admitted);
    assert!(!report.trace_rust_native_admitted);
    assert!(!report.default_switch_allowed);
    assert!(report.formal_kernel_program_parity_stage_required);
    assert!(report.c_tproxy_object_fallback_required);
    assert!(report.c_trace_object_fallback_required);
    assert!(report.tc_command_fallback_required);
    assert!(report.go_userspace_control_plane_authoritative);
    assert!(!report.go_bpf_loader_restored_by_this_stage);
    assert!(!report.go_bpf_fallback_deletion_allowed_by_this_stage);
}

#[test]
fn kernel_program_feasibility_covers_all_tproxy_classifier_and_cgroup_sections() {
    let coverage = tproxy_kernel_program_coverage();
    assert_eq!(coverage.len(), 16);

    let classifiers = coverage
        .iter()
        .filter(|line| line.surface == KernelProgramSurface::TproxyClassifier)
        .collect::<Vec<_>>();
    assert_eq!(classifiers.len(), 10);
    assert_eq!(classifiers[0].c_section, "tc/lan_ingress_l2");
    assert_eq!(
        classifiers[0].rust_section,
        Some("classifier/lan_ingress_l2")
    );
    assert_eq!(classifiers[0].program_name, "tproxy_lan_ingress_l2");
    assert!(classifiers.iter().all(|line| {
        line.status == KernelProgramCoverageStatus::RustNativeAdmitted
            && line
                .rust_section
                .is_some_and(|section| section.starts_with("classifier/"))
    }));

    let cgroups = coverage
        .iter()
        .filter(|line| line.surface == KernelProgramSurface::TproxyCgroup)
        .collect::<Vec<_>>();
    assert_eq!(cgroups.len(), dae_cgroup_attach_matrix().len());
    assert_eq!(cgroups[0].c_section, "cgroup/sock_create");
    assert_eq!(cgroups[0].rust_section, Some("cgroup/sock_create"));
    assert_eq!(cgroups[0].program_name, "tproxy_wan_cg_sock_create");
    assert!(
        cgroups
            .iter()
            .all(|line| line.status == KernelProgramCoverageStatus::RustNativeAdmitted)
    );
}

#[test]
fn kernel_program_feasibility_keeps_trace_c_object_as_oracle() {
    let trace = trace_kernel_program_coverage();
    assert_eq!(trace.len(), 6);
    assert_eq!(trace[0].surface, KernelProgramSurface::TraceKprobe);
    assert_eq!(trace[0].c_section, "kprobe/skb-1");
    assert_eq!(trace[0].rust_section, None);
    assert_eq!(trace[0].program_name, "kprobe_skb_1");
    assert!(
        trace
            .iter()
            .all(|line| line.status == KernelProgramCoverageStatus::COracleRequired)
    );
}

#[test]
fn kernel_program_parity_admission_blocks_fallback_deletion_after_feasibility_only() {
    let feasibility = kernel_program_feasibility_report();
    let evidence = KernelProgramParityEvidence::from_feasibility(&feasibility);
    let report = kernel_program_parity_admission_report(evidence);
    assert_eq!(report.schema, "kernel-program-parity-admission-v1");
    assert!(!report.admitted);
    assert!(!report.default_switch_allowed);
    assert!(!report.c_tproxy_object_deletion_allowed);
    assert!(!report.c_trace_object_deletion_allowed);
    assert!(!report.go_bpf_fallback_deletion_allowed);
    assert!(report.fallback_required);
    assert!(
        !report
            .missing_checks
            .contains(&KernelProgramParityCheck::TproxyClassifierCoverage)
    );
    assert!(
        !report
            .missing_checks
            .contains(&KernelProgramParityCheck::TproxyCgroupCoverage)
    );
    assert!(
        !report
            .missing_checks
            .contains(&KernelProgramParityCheck::RuntimeAdmission)
    );
    assert!(
        !report
            .missing_checks
            .contains(&KernelProgramParityCheck::MapAbiBtfVerifierParity)
    );
    assert!(
        report
            .missing_checks
            .contains(&KernelProgramParityCheck::TraceKprobeCoverage)
    );
    assert!(
        !report
            .missing_checks
            .contains(&KernelProgramParityCheck::PacketLevelGoldenParity)
    );
    assert!(
        !report
            .missing_checks
            .contains(&KernelProgramParityCheck::MatchedGoRustBenchmark)
    );
    assert!(
        !report
            .missing_checks
            .contains(&KernelProgramParityCheck::RemoteHostWriteAdmission)
    );
    assert!(report.evidence_queue.iter().any(|line| line.check
        == KernelProgramParityCheck::PacketLevelGoldenParity
        && line.item == "l2_ipv4_tcp"
        && line.status == KernelProgramParityEvidenceStatus::Passed));
    assert!(report.evidence_queue.iter().any(|line| line.check
        == KernelProgramParityCheck::MapAbiBtfVerifierParity
        && line.item == "abi_layout_golden_fixture"
        && line.status == KernelProgramParityEvidenceStatus::Passed));
    assert!(report.evidence_queue.iter().any(|line| line.check
        == KernelProgramParityCheck::MapAbiBtfVerifierParity
        && line.item == "rust_object_btf_timer_verifier_admission"
        && line.status == KernelProgramParityEvidenceStatus::Passed));
    assert!(report.evidence_queue.iter().any(|line| line.check
        == KernelProgramParityCheck::MapAbiBtfVerifierParity
        && line.item == "c_vs_rust_object_map_catalog_diff"
        && line.status == KernelProgramParityEvidenceStatus::Passed));
    assert!(report.evidence_queue.iter().any(|line| line.check
        == KernelProgramParityCheck::MatchedGoRustBenchmark
        && line.item == "count10_same_corpus_default_daemon_ready_benchmark"
        && line.status == KernelProgramParityEvidenceStatus::Passed));
    assert!(report.evidence_queue.iter().any(|line| line.check
        == KernelProgramParityCheck::RemoteHostWriteAdmission
        && line.item == "remote_host_write_runtime_admission"
        && line.status == KernelProgramParityEvidenceStatus::Passed));
    assert!(report.evidence_queue.iter().any(|line| line.check
        == KernelProgramParityCheck::RemoteHostWriteAdmission
        && line.item == "remote_38_root_gated_runtime_owner_passed"
        && line.status == KernelProgramParityEvidenceStatus::Passed));
    assert!(report.evidence_queue.iter().any(|line| line.check
        == KernelProgramParityCheck::TraceKprobeCoverage
        && line.item == "rust_trace_load_pin_smoke"
        && line.status == KernelProgramParityEvidenceStatus::Passed));
    assert!(report.evidence_queue.iter().any(|line| line.check
        == KernelProgramParityCheck::TraceKprobeCoverage
        && line.item == "rust_trace_attach_and_ringbuf_smoke"
        && line.status == KernelProgramParityEvidenceStatus::Passed));
    assert!(report.evidence_queue.iter().any(|line| line.check
        == KernelProgramParityCheck::TraceKprobeCoverage
        && line.item == "rust_skb_core_read_semantics"
        && line.status == KernelProgramParityEvidenceStatus::Missing));
}

#[test]
fn kernel_program_parity_admission_can_record_complete_evidence_without_opening_switch() {
    let report =
        kernel_program_parity_admission_report(KernelProgramParityEvidence::complete_for_tests());
    assert!(report.admitted);
    assert!(report.missing_checks.is_empty());
    assert!(!report.default_switch_allowed);
    assert!(!report.c_tproxy_object_deletion_allowed);
    assert!(!report.c_trace_object_deletion_allowed);
    assert!(!report.go_bpf_fallback_deletion_allowed);
    assert!(report.fallback_required);
}

#[test]
fn tproxy_dataplane_admission_excludes_trace_diagnostic_gate() {
    let feasibility = kernel_program_feasibility_report();
    let evidence = KernelProgramParityEvidence::from_feasibility(&feasibility);
    let report = tproxy_dataplane_admission_report(evidence);

    assert_eq!(report.schema, "tproxy-dataplane-admission-v1");
    assert!(report.admitted);
    assert!(report.default_candidate_allowed);
    assert!(report.go_bpf_loader_retirement_candidate);
    assert!(report.c_tproxy_object_retirement_candidate);
    assert!(!report.c_tproxy_object_required);
    assert!(!report.c_trace_object_required);
    assert!(report.trace_diagnostic_excluded_from_default_candidate);
    assert!(report.tc_command_fallback_required);
    assert!(report.go_userspace_control_plane_preserved);
    assert!(
        !report
            .required_checks
            .contains(&KernelProgramParityCheck::TraceKprobeCoverage)
    );
    assert!(
        !report
            .missing_checks
            .contains(&KernelProgramParityCheck::TraceKprobeCoverage)
    );
    assert!(report.missing_checks.is_empty());
    assert!(!report.evidence_queue.iter().any(|line| {
        line.check == KernelProgramParityCheck::TraceKprobeCoverage
            || line.item.starts_with("trace_")
            || line.item.contains("core_read")
    }));
}

#[test]
fn trace_diagnostic_gate_is_retired_outside_tproxy_default_candidate() {
    let report = trace_diagnostic_gate_report(&trace_core_sideload_gate_report());

    assert_eq!(report.schema, "trace-diagnostic-gate-v1");
    assert_eq!(report.status, "retired_from_product_default");
    assert!(!report.participates_in_tproxy_default_candidate);
    assert!(!report.c_trace_object_required);
    assert!(!report.go_trace_fallback_required);
    assert!(!report.rust_core_sideload_enabled);
    assert!(report.fallback_retirement_allowed);
    assert!(report.missing_checks.is_empty());
    assert!(report.evidence_queue.iter().any(|line| {
        line.check == KernelProgramParityCheck::TraceKprobeCoverage
            && line.item == "rust_skb_core_read_semantics"
            && line.status == KernelProgramParityEvidenceStatus::Missing
    }));
}

#[test]
fn kernel_program_fallback_retirement_gate_blocks_current_incomplete_state() {
    let feasibility = kernel_program_feasibility_report();
    let evidence = KernelProgramParityEvidence::from_feasibility(&feasibility);
    let tproxy = tproxy_dataplane_admission_report(evidence);
    let trace_diagnostic = trace_diagnostic_gate_report(&trace_core_sideload_gate_report());
    let gate = kernel_program_fallback_retirement_gate_report(
        &tproxy,
        &trace_diagnostic,
        KernelProgramFallbackRetirementEvidence::read_only(),
    );

    assert_eq!(gate.schema, "kernel-program-fallback-retirement-gate-v1");
    assert!(!gate.admitted);
    assert!(!gate.default_switch_allowed);
    assert!(!gate.c_tproxy_object_retirement_allowed);
    assert!(!gate.c_trace_object_retirement_allowed);
    assert!(!gate.go_bpf_fallback_retirement_allowed);
    assert!(!gate.tc_command_fallback_retirement_allowed);
    assert!(!gate.trace_diagnostic_retirement_allowed);
    assert!(gate.c_tproxy_object_required);
    assert!(!gate.c_trace_object_required);
    assert!(gate.go_bpf_fallback_required);
    assert!(!gate.go_trace_fallback_required);
    assert!(gate.tc_command_fallback_required);
    assert!(gate.go_userspace_control_plane_preserved);
    assert_eq!(
        gate.retirement_scope,
        "kernel-facing-tproxy-default-rust-aya; trace diagnostic retired from product default; outbound protocol boundary preserved"
    );
    assert!(!gate.explicit_user_approval_recorded);
    assert!(!gate.product_chain_recertified);
    assert!(
        !gate
            .blockers
            .contains(&KernelProgramFallbackRetirementBlocker::KernelProgramParityMissing)
    );
    assert!(
        !gate
            .blockers
            .contains(&KernelProgramFallbackRetirementBlocker::TproxyDataplaneAdmissionMissing)
    );
    assert!(
        !gate
            .blockers
            .contains(&KernelProgramFallbackRetirementBlocker::TraceCoreSideloadDisabled)
    );
    assert!(
        !gate
            .blockers
            .contains(&KernelProgramFallbackRetirementBlocker::RemoteHostWriteAdmissionMissing)
    );
    assert!(
        gate.blockers
            .contains(&KernelProgramFallbackRetirementBlocker::ExplicitUserApprovalMissing)
    );
    assert!(
        gate.blockers
            .contains(&KernelProgramFallbackRetirementBlocker::ProductChainRecertificationMissing)
    );
    assert!(
        !gate
            .missing_parity_checks
            .contains(&KernelProgramParityCheck::TraceKprobeCoverage)
    );
    assert!(
        !gate
            .missing_parity_checks
            .contains(&KernelProgramParityCheck::RemoteHostWriteAdmission)
    );
}

#[test]
fn kernel_program_fallback_retirement_gate_can_admit_only_after_full_evidence() {
    let tproxy =
        tproxy_dataplane_admission_report(KernelProgramParityEvidence::complete_for_tests());
    let trace_diagnostic = trace_diagnostic_gate_report(&trace_core_sideload_gate_report());
    let gate = kernel_program_fallback_retirement_gate_report(
        &tproxy,
        &trace_diagnostic,
        KernelProgramFallbackRetirementEvidence::completed_for_tests(),
    );

    assert!(gate.admitted);
    assert!(gate.default_switch_allowed);
    assert!(gate.c_tproxy_object_retirement_allowed);
    assert!(gate.c_trace_object_retirement_allowed);
    assert!(gate.go_bpf_fallback_retirement_allowed);
    assert!(!gate.tc_command_fallback_retirement_allowed);
    assert!(gate.trace_diagnostic_retirement_allowed);
    assert!(!gate.c_tproxy_object_required);
    assert!(!gate.c_trace_object_required);
    assert!(!gate.go_bpf_fallback_required);
    assert!(!gate.go_trace_fallback_required);
    assert!(gate.tc_command_fallback_required);
    assert!(gate.go_userspace_control_plane_preserved);
    assert!(gate.explicit_user_approval_recorded);
    assert!(gate.product_chain_recertified);
    assert!(gate.blockers.is_empty());
    assert!(gate.missing_parity_checks.is_empty());
}

#[test]
fn kernel_program_parity_evidence_queue_names_packet_and_map_admission_gap() {
    let packet = packet_level_golden_evidence_queue();
    assert_eq!(packet.len(), 11);
    assert!(packet.iter().all(|line| line.check
        == KernelProgramParityCheck::PacketLevelGoldenParity
        && line.status == KernelProgramParityEvidenceStatus::Passed
        && line.required_before_default));
    assert!(packet.iter().any(|line| line.item == "l2_ipv6_udp"));
    assert!(
        packet
            .iter()
            .any(|line| line.item == "unsupported_l4_protocol_pass")
    );
    assert!(
        packet
            .iter()
            .any(|line| line.item == "truncated_packet_no_drop")
    );

    let map = map_abi_btf_verifier_evidence_queue();
    assert_eq!(map.len(), 6);
    assert!(
        map.iter()
            .any(|line| line.item == "map_catalog_golden_fixture"
                && line.status == KernelProgramParityEvidenceStatus::Passed)
    );
    assert!(map.iter().all(
        |line| line.check == KernelProgramParityCheck::MapAbiBtfVerifierParity
            && line.status == KernelProgramParityEvidenceStatus::Passed
            && line.required_before_default
    ));
    assert!(
        map.iter()
            .any(|line| line.item == "pinned_map_upgrade_retry_parity"
                && line.status == KernelProgramParityEvidenceStatus::Passed)
    );
    assert!(map_abi_btf_verifier_evidence_admitted());
    assert!(packet_level_golden_evidence_admitted());

    let matched = matched_go_rust_benchmark_evidence_queue();
    assert_eq!(matched.len(), 1);
    assert!(matched.iter().all(|line| line.check
        == KernelProgramParityCheck::MatchedGoRustBenchmark
        && line.status == KernelProgramParityEvidenceStatus::Passed
        && line.required_before_default));
    assert!(
        matched
            .iter()
            .any(|line| line.item == "count10_same_corpus_default_daemon_ready_benchmark")
    );
    assert!(matched_go_rust_benchmark_evidence_admitted());

    let remote = remote_host_write_runtime_evidence_queue();
    assert_eq!(remote.len(), 5);
    assert!(remote.iter().all(|line| line.check
        == KernelProgramParityCheck::RemoteHostWriteAdmission
        && line.status == KernelProgramParityEvidenceStatus::Passed
        && line.required_before_default));
    assert!(
        remote
            .iter()
            .any(|line| line.item == "remote_38_active_tcp_udp_dns_admitted")
    );
    assert!(remote_host_write_runtime_evidence_admitted());
}
