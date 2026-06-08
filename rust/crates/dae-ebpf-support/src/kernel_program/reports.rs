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
        default_switch_allowed: false,
        c_tproxy_object_deletion_allowed: false,
        c_trace_object_deletion_allowed: false,
        go_bpf_fallback_deletion_allowed: false,
        fallback_required: true,
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
        default_candidate_allowed: admitted,
        go_bpf_loader_retirement_candidate: admitted,
        c_tproxy_object_retirement_candidate: admitted,
        c_tproxy_object_required: !admitted,
        c_trace_object_required: false,
        trace_diagnostic_excluded_from_default_candidate: true,
        tc_command_fallback_required: true,
        go_userspace_control_plane_preserved: evidence.go_userspace_boundary_preserved,
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
        status: "retired_from_product_default",
        participates_in_tproxy_default_candidate: false,
        c_trace_object_required: trace_gate.c_trace_object_required,
        go_trace_fallback_required: trace_gate.go_trace_fallback_required,
        rust_core_sideload_enabled: trace_gate.enabled,
        fallback_retirement_allowed: !trace_gate.c_trace_object_required
            && !trace_gate.go_trace_fallback_required,
        missing_checks: Vec::new(),
        evidence_queue: trace_kprobe_evidence_queue(),
        restore_gate: trace_gate.restore_gate,
    }
}

pub fn kernel_program_fallback_retirement_gate_report(
    tproxy_admission: &TproxyDataplaneAdmissionReport,
    trace_diagnostic: &TraceDiagnosticGateReport,
    evidence: KernelProgramFallbackRetirementEvidence,
) -> KernelProgramFallbackRetirementGateReport {
    let mut blockers = Vec::new();
    if !tproxy_admission.admitted {
        blockers.push(KernelProgramFallbackRetirementBlocker::TproxyDataplaneAdmissionMissing);
    }
    if tproxy_admission
        .missing_checks
        .contains(&KernelProgramParityCheck::RemoteHostWriteAdmission)
    {
        blockers.push(KernelProgramFallbackRetirementBlocker::RemoteHostWriteAdmissionMissing);
    }
    if !evidence.explicit_user_approval {
        blockers.push(KernelProgramFallbackRetirementBlocker::ExplicitUserApprovalMissing);
    }
    if !evidence.product_chain_recertified {
        blockers.push(KernelProgramFallbackRetirementBlocker::ProductChainRecertificationMissing);
    }

    let admitted = blockers.is_empty();
    let trace_retirement_allowed = admitted && trace_diagnostic.fallback_retirement_allowed;
    KernelProgramFallbackRetirementGateReport {
        schema: "kernel-program-fallback-retirement-gate",
        admitted,
        default_switch_allowed: admitted,
        c_tproxy_object_retirement_allowed: admitted,
        c_trace_object_retirement_allowed: trace_retirement_allowed,
        go_bpf_fallback_retirement_allowed: admitted,
        tc_command_fallback_retirement_allowed: false,
        trace_diagnostic_retirement_allowed: trace_retirement_allowed,
        c_tproxy_object_required: !admitted,
        c_trace_object_required: trace_diagnostic.c_trace_object_required
            && !trace_retirement_allowed,
        go_bpf_fallback_required: !admitted,
        go_trace_fallback_required: trace_diagnostic.go_trace_fallback_required,
        tc_command_fallback_required: true,
        go_userspace_control_plane_preserved: true,
        retirement_scope: "kernel-facing-tproxy-default-rust-aya; trace diagnostic retired from product default; outbound protocol boundary preserved",
        explicit_user_approval_recorded: evidence.explicit_user_approval,
        product_chain_recertified: evidence.product_chain_recertified,
        blockers,
        missing_parity_checks: tproxy_admission.missing_checks.clone(),
        trace_restore_gate: trace_diagnostic.restore_gate,
    }
}
