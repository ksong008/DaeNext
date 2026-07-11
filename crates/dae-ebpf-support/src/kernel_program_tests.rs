use crate::*;

#[test]
fn kernel_program_feasibility_reports_native_production_candidate() {
    let report = kernel_program_feasibility_report();
    assert_eq!(report.schema, "kernel-program-feasibility");
    assert_eq!(report.tproxy_classifier_total, 10);
    assert_eq!(report.rust_tproxy_classifier_covered, 10);
    assert_eq!(report.tproxy_cgroup_total, 6);
    assert_eq!(report.rust_tproxy_cgroup_covered, 6);
    assert_eq!(report.trace_kprobe_total, 6);
    assert_eq!(report.rust_trace_kprobe_covered, 0);
    assert!(report.rust_tproxy_runtime_admitted);
    assert!(!report.trace_rust_native_admitted);
    assert!(!report.production_admission_allowed);
    assert!(report.kernel_program_parity_required_before_production);
    assert!(!report.external_ebpf_tproxy_object_required);
    assert!(!report.external_ebpf_trace_object_required);
    assert!(report.tc_command_backend_required);
    assert!(report.native_userspace_control_plane_ready);
    assert!(report.native_bpf_loader_production_ready);
    assert!(report.external_bpf_dependency_absent_before_production);
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
    assert_eq!(classifiers[0].section, "tc/lan_ingress_l2");
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
    assert_eq!(cgroups[0].section, "cgroup/sock_create");
    assert_eq!(cgroups[0].rust_section, Some("cgroup/sock_create"));
    assert_eq!(cgroups[0].program_name, "tproxy_wan_cg_sock_create");
    assert!(
        cgroups
            .iter()
            .all(|line| line.status == KernelProgramCoverageStatus::RustNativeAdmitted)
    );
}

#[test]
fn kernel_program_feasibility_keeps_trace_diagnostic_disabled() {
    let trace = trace_kernel_program_coverage();
    assert_eq!(trace.len(), 6);
    assert_eq!(trace[0].surface, KernelProgramSurface::TraceKprobe);
    assert_eq!(trace[0].section, "kprobe/skb-1");
    assert_eq!(trace[0].rust_section, None);
    assert_eq!(trace[0].program_name, "kprobe_skb_1");
    assert!(
        trace
            .iter()
            .all(|line| line.status == KernelProgramCoverageStatus::NativeTraceDisabled)
    );
}

#[test]
fn kernel_program_parity_admission_blocks_external_dependency_release_after_feasibility_only() {
    let feasibility = kernel_program_feasibility_report();
    let evidence = KernelProgramParityEvidence::from_feasibility(&feasibility);
    let report = kernel_program_parity_admission_report(evidence);
    assert_eq!(report.schema, "kernel-program-parity-admission");
    assert!(!report.admitted);
    assert!(!report.production_admission_allowed);
    assert!(report.external_ebpf_tproxy_object_absent);
    assert!(report.external_ebpf_trace_object_absent);
    assert!(report.external_bpf_dependency_absent);
    assert!(report.additional_evidence_required);
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
            .contains(&KernelProgramParityCheck::NativeBenchmark)
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
        && line.item == "native_object_map_catalog_contract"
        && line.status == KernelProgramParityEvidenceStatus::Passed));
    assert!(report.evidence_queue.iter().any(|line| line.check
        == KernelProgramParityCheck::NativeBenchmark
        && line.item == "count10_native_daemon_ready_benchmark"
        && line.status == KernelProgramParityEvidenceStatus::Passed));
    assert!(report.evidence_queue.iter().any(|line| line.check
        == KernelProgramParityCheck::RemoteHostWriteAdmission
        && line.item == "remote_host_write_runtime_admission"
        && line.status == KernelProgramParityEvidenceStatus::Passed));
    assert!(report.evidence_queue.iter().any(|line| line.check
        == KernelProgramParityCheck::RemoteHostWriteAdmission
        && line.item == "scoped_host_root_gated_runtime_owner_passed"
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
    assert!(!report.production_admission_allowed);
    assert!(report.external_ebpf_tproxy_object_absent);
    assert!(report.external_ebpf_trace_object_absent);
    assert!(report.external_bpf_dependency_absent);
    assert!(!report.additional_evidence_required);
}

#[test]
fn tproxy_dataplane_admission_excludes_trace_diagnostic_gate() {
    let feasibility = kernel_program_feasibility_report();
    let evidence = KernelProgramParityEvidence::from_feasibility(&feasibility);
    let report = tproxy_dataplane_admission_report(evidence);

    assert_eq!(report.schema, "tproxy-dataplane-admission");
    assert!(report.admitted);
    assert!(report.production_candidate_allowed);
    assert!(report.native_bpf_loader_production_candidate);
    assert!(report.external_ebpf_tproxy_object_absent);
    assert!(!report.external_ebpf_tproxy_object_required);
    assert!(!report.external_ebpf_trace_object_required);
    assert!(report.trace_diagnostic_excluded_from_production_candidate);
    assert!(report.tc_command_backend_required);
    assert!(report.native_userspace_control_plane_ready);
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
fn trace_diagnostic_gate_is_excluded_from_tproxy_production_candidate() {
    let report = trace_diagnostic_gate_report(&trace_core_sideload_gate_report());

    assert_eq!(report.schema, "trace-diagnostic-gate");
    assert_eq!(report.status, "excluded_from_production_runtime");
    assert!(!report.participates_in_tproxy_production_candidate);
    assert!(!report.external_ebpf_trace_object_required);
    assert!(!report.external_trace_dependency_required);
    assert!(!report.rust_core_sideload_enabled);
    assert!(report.native_trace_restore_allowed);
    assert!(report.missing_checks.is_empty());
    assert!(report.evidence_queue.iter().any(|line| {
        line.check == KernelProgramParityCheck::TraceKprobeCoverage
            && line.item == "rust_skb_core_read_semantics"
            && line.status == KernelProgramParityEvidenceStatus::Missing
    }));
}

#[test]
fn kernel_program_production_admission_gate_blocks_current_incomplete_state() {
    let feasibility = kernel_program_feasibility_report();
    let evidence = KernelProgramParityEvidence::from_feasibility(&feasibility);
    let tproxy = tproxy_dataplane_admission_report(evidence);
    let trace_diagnostic = trace_diagnostic_gate_report(&trace_core_sideload_gate_report());
    let gate = kernel_program_production_admission_gate_report(
        &tproxy,
        &trace_diagnostic,
        KernelProgramProductionEvidence::read_only(),
    );

    assert_eq!(gate.schema, "kernel-program-production-gate");
    assert!(!gate.admitted);
    assert!(!gate.production_admission_allowed);
    assert!(gate.external_ebpf_tproxy_object_absent);
    assert!(gate.external_ebpf_trace_object_absent);
    assert!(gate.external_bpf_dependency_absent);
    assert!(!gate.trace_diagnostic_restore_allowed);
    assert!(!gate.external_ebpf_tproxy_object_required);
    assert!(!gate.external_ebpf_trace_object_required);
    assert!(!gate.external_trace_dependency_required);
    assert!(gate.tc_command_backend_required);
    assert!(gate.native_userspace_control_plane_ready);
    assert_eq!(
        gate.production_scope,
        "kernel-facing-tproxy-rust-aya; trace diagnostic excluded from production runtime; outbound protocol boundary ready"
    );
    assert!(!gate.explicit_user_approval_recorded);
    assert!(!gate.final_state_certified);
    assert!(
        !gate
            .blockers
            .contains(&KernelProgramProductionBlocker::KernelProgramParityMissing)
    );
    assert!(
        !gate
            .blockers
            .contains(&KernelProgramProductionBlocker::TproxyDataplaneAdmissionMissing)
    );
    assert!(
        !gate
            .blockers
            .contains(&KernelProgramProductionBlocker::TraceCoreSideloadDisabled)
    );
    assert!(
        !gate
            .blockers
            .contains(&KernelProgramProductionBlocker::RemoteHostWriteAdmissionMissing)
    );
    assert!(
        gate.blockers
            .contains(&KernelProgramProductionBlocker::ExplicitUserApprovalMissing)
    );
    assert!(
        gate.blockers
            .contains(&KernelProgramProductionBlocker::FinalStateCertificationMissing)
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
fn kernel_program_production_admission_gate_can_admit_only_after_full_evidence() {
    let tproxy =
        tproxy_dataplane_admission_report(KernelProgramParityEvidence::complete_for_tests());
    let trace_diagnostic = trace_diagnostic_gate_report(&trace_core_sideload_gate_report());
    let gate = kernel_program_production_admission_gate_report(
        &tproxy,
        &trace_diagnostic,
        KernelProgramProductionEvidence::completed_for_tests(),
    );

    assert!(gate.admitted);
    assert!(gate.production_admission_allowed);
    assert!(gate.external_ebpf_tproxy_object_absent);
    assert!(gate.external_ebpf_trace_object_absent);
    assert!(gate.external_bpf_dependency_absent);
    assert!(gate.trace_diagnostic_restore_allowed);
    assert!(!gate.external_ebpf_tproxy_object_required);
    assert!(!gate.external_ebpf_trace_object_required);
    assert!(!gate.external_trace_dependency_required);
    assert!(gate.tc_command_backend_required);
    assert!(gate.native_userspace_control_plane_ready);
    assert!(gate.explicit_user_approval_recorded);
    assert!(gate.final_state_certified);
    assert!(gate.blockers.is_empty());
    assert!(gate.missing_parity_checks.is_empty());
}

#[test]
fn kernel_program_parity_evidence_queue_names_packet_and_map_admission_gap() {
    let packet = packet_level_golden_evidence_queue();
    assert_eq!(packet.len(), packet_level_golden_cases().len());
    assert!(packet.iter().all(|line| line.check
        == KernelProgramParityCheck::PacketLevelGoldenParity
        && line.status == KernelProgramParityEvidenceStatus::Passed
        && line.required_before_production_admission));
    assert!(packet.iter().any(|line| line.item == "l2_ipv6_udp"));
    assert!(
        packet
            .iter()
            .any(|line| line.item == "ipv4_non_initial_fragment_pass")
    );
    assert!(
        packet
            .iter()
            .any(|line| line.item == "ipv6_non_initial_fragment_pass")
    );
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
            && line.required_before_production_admission
    ));
    assert!(
        map.iter()
            .any(|line| line.item == "pinned_map_upgrade_retry_parity"
                && line.status == KernelProgramParityEvidenceStatus::Passed)
    );
    assert!(map_abi_btf_verifier_evidence_admitted());
    assert!(packet_level_golden_evidence_admitted());

    let matched = native_benchmark_evidence_queue();
    assert_eq!(matched.len(), 1);
    assert!(matched.iter().all(
        |line| line.check == KernelProgramParityCheck::NativeBenchmark
            && line.status == KernelProgramParityEvidenceStatus::Passed
            && line.required_before_production_admission
    ));
    assert!(
        matched
            .iter()
            .any(|line| line.item == "count10_native_daemon_ready_benchmark")
    );
    assert!(native_benchmark_evidence_admitted());

    let remote = remote_host_write_runtime_evidence_queue();
    assert_eq!(remote.len(), 5);
    assert!(remote.iter().all(|line| line.check
        == KernelProgramParityCheck::RemoteHostWriteAdmission
        && line.status == KernelProgramParityEvidenceStatus::Passed
        && line.required_before_production_admission));
    assert!(
        remote
            .iter()
            .any(|line| line.item == "scoped_host_active_tcp_udp_dns_admitted")
    );
    assert!(remote_host_write_runtime_evidence_admitted());
}
