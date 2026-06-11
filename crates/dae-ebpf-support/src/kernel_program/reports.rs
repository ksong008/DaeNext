use super::*;
pub fn kernel_program_parity_admission_report(
    evidence: KernelProgramParityEvidence,
) -> KernelProgramParityAdmissionReport {
    let required_checks = kernel_program_parity_required_checks();
    let missing_checks = required_checks
        .iter()
        .copied()
        .filter(|check| !kernel_program_parity_check_passed(evidence, *check))
        .collect::<Vec<_>>();
    let admitted = missing_checks.is_empty();
    KernelProgramParityAdmissionReport {
        schema: "kernel-program-parity-admission",
        admitted,
        production_admission_allowed: false,
        external_ebpf_tproxy_object_absent: evidence.external_ebpf_object_absent,
        external_ebpf_trace_object_absent: evidence.external_ebpf_object_absent,
        external_bpf_dependency_absent: true,
        additional_evidence_required: !admitted,
        required_checks,
        missing_checks,
        evidence_queue: kernel_program_parity_evidence_queue(evidence),
    }
}

pub fn tproxy_dataplane_admission_report(
    evidence: KernelProgramParityEvidence,
) -> TproxyDataplaneAdmissionReport {
    let required_checks = tproxy_dataplane_required_checks();
    let missing_checks = required_checks
        .iter()
        .copied()
        .filter(|check| !kernel_program_parity_check_passed(evidence, *check))
        .collect::<Vec<_>>();
    let admitted = missing_checks.is_empty();
    TproxyDataplaneAdmissionReport {
        schema: "tproxy-dataplane-admission",
        admitted,
        production_candidate_allowed: admitted,
        native_bpf_loader_production_candidate: admitted,
        external_ebpf_tproxy_object_absent: evidence.external_ebpf_object_absent,
        external_ebpf_tproxy_object_required: false,
        external_ebpf_trace_object_required: false,
        trace_diagnostic_excluded_from_production_candidate: true,
        tc_command_backend_required: true,
        native_userspace_control_plane_ready: evidence.native_userspace_boundary_ready,
        required_checks,
        missing_checks,
        evidence_queue: tproxy_dataplane_evidence_queue(evidence),
    }
}

pub fn trace_diagnostic_gate_report(
    trace_gate: &TraceCoreSideloadGateReport,
) -> TraceDiagnosticGateReport {
    TraceDiagnosticGateReport {
        schema: "trace-diagnostic-gate",
        status: "excluded_from_production_runtime",
        participates_in_tproxy_production_candidate: false,
        external_ebpf_trace_object_required: trace_gate.external_ebpf_trace_object_required,
        external_trace_dependency_required: trace_gate.external_trace_dependency_required,
        rust_core_sideload_enabled: trace_gate.enabled,
        native_trace_restore_allowed: !trace_gate.external_ebpf_trace_object_required
            && !trace_gate.external_trace_dependency_required,
        missing_checks: Vec::new(),
        evidence_queue: trace_kprobe_evidence_queue(),
        restore_gate: trace_gate.restore_gate,
    }
}

pub fn kernel_program_production_admission_gate_report(
    tproxy_admission: &TproxyDataplaneAdmissionReport,
    trace_diagnostic: &TraceDiagnosticGateReport,
    evidence: KernelProgramProductionEvidence,
) -> KernelProgramProductionGateReport {
    let mut blockers = Vec::new();
    if !tproxy_admission.admitted {
        blockers.push(KernelProgramProductionBlocker::TproxyDataplaneAdmissionMissing);
    }
    if tproxy_admission
        .missing_checks
        .contains(&KernelProgramParityCheck::RemoteHostWriteAdmission)
    {
        blockers.push(KernelProgramProductionBlocker::RemoteHostWriteAdmissionMissing);
    }
    if !evidence.explicit_user_approval {
        blockers.push(KernelProgramProductionBlocker::ExplicitUserApprovalMissing);
    }
    if !evidence.final_state_certified {
        blockers.push(KernelProgramProductionBlocker::FinalStateCertificationMissing);
    }

    let admitted = blockers.is_empty();
    let trace_restore_allowed = admitted && trace_diagnostic.native_trace_restore_allowed;
    KernelProgramProductionGateReport {
        schema: "kernel-program-production-gate",
        admitted,
        production_admission_allowed: admitted,
        external_ebpf_tproxy_object_absent: true,
        external_ebpf_trace_object_absent: true,
        external_bpf_dependency_absent: true,
        tc_command_backend_required: true,
        trace_diagnostic_restore_allowed: trace_restore_allowed,
        external_ebpf_tproxy_object_required: false,
        external_ebpf_trace_object_required: false,
        external_trace_dependency_required: trace_diagnostic.external_trace_dependency_required,
        native_userspace_control_plane_ready: true,
        production_scope: "kernel-facing-tproxy-rust-aya; trace diagnostic excluded from production runtime; outbound protocol boundary ready",
        explicit_user_approval_recorded: evidence.explicit_user_approval,
        final_state_certified: evidence.final_state_certified,
        blockers,
        missing_parity_checks: tproxy_admission.missing_checks.clone(),
        trace_restore_gate: trace_diagnostic.restore_gate,
    }
}
