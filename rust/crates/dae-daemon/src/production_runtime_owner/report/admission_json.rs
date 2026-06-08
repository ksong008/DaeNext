use super::*;
pub(super) fn kernel_program_parity_admission_json(
    report: &KernelProgramParityAdmissionReport,
) -> Value {
    json!({
        "schema": report.schema,
        "admitted": report.admitted,
        "default_switch_allowed": report.default_switch_allowed,
        "c_tproxy_object_deletion_allowed": report.c_tproxy_object_deletion_allowed,
        "c_trace_object_deletion_allowed": report.c_trace_object_deletion_allowed,
        "go_bpf_fallback_deletion_allowed": report.go_bpf_fallback_deletion_allowed,
        "fallback_required": report.fallback_required,
        "required_checks": report
            .required_checks
            .iter()
            .map(|check| check.as_str())
            .collect::<Vec<_>>(),
        "missing_checks": report
            .missing_checks
            .iter()
            .map(|check| check.as_str())
            .collect::<Vec<_>>(),
        "evidence_queue": report
            .evidence_queue
            .iter()
            .map(|line| json!({
                "check": line.check.as_str(),
                "item": line.item,
                "status": line.status.as_str(),
                "source": line.source,
                "required_before_default": line.required_before_default,
            }))
            .collect::<Vec<_>>(),
    })
}

pub(super) fn tproxy_dataplane_admission_json(report: &TproxyDataplaneAdmissionReport) -> Value {
    json!({
        "schema": report.schema,
        "admitted": report.admitted,
        "default_candidate_allowed": report.default_candidate_allowed,
        "go_bpf_loader_retirement_candidate": report.go_bpf_loader_retirement_candidate,
        "c_tproxy_object_retirement_candidate": report.c_tproxy_object_retirement_candidate,
        "c_tproxy_object_required": report.c_tproxy_object_required,
        "c_trace_object_required": report.c_trace_object_required,
        "trace_diagnostic_excluded_from_default_candidate": report.trace_diagnostic_excluded_from_default_candidate,
        "tc_command_fallback_required": report.tc_command_fallback_required,
        "go_userspace_control_plane_preserved": report.go_userspace_control_plane_preserved,
        "required_checks": report
            .required_checks
            .iter()
            .map(|check| check.as_str())
            .collect::<Vec<_>>(),
        "missing_checks": report
            .missing_checks
            .iter()
            .map(|check| check.as_str())
            .collect::<Vec<_>>(),
        "evidence_queue": report
            .evidence_queue
            .iter()
            .map(|line| json!({
                "check": line.check.as_str(),
                "item": line.item,
                "status": line.status.as_str(),
                "source": line.source,
                "required_before_default": line.required_before_default,
            }))
            .collect::<Vec<_>>(),
    })
}

pub(super) fn trace_diagnostic_gate_json(report: &TraceDiagnosticGateReport) -> Value {
    json!({
        "schema": report.schema,
        "status": report.status,
        "participates_in_tproxy_default_candidate": report.participates_in_tproxy_default_candidate,
        "c_trace_object_required": report.c_trace_object_required,
        "go_trace_fallback_required": report.go_trace_fallback_required,
        "rust_core_sideload_enabled": report.rust_core_sideload_enabled,
        "fallback_retirement_allowed": report.fallback_retirement_allowed,
        "missing_checks": report
            .missing_checks
            .iter()
            .map(|check| check.as_str())
            .collect::<Vec<_>>(),
        "evidence_queue": report
            .evidence_queue
            .iter()
            .map(|line| json!({
                "check": line.check.as_str(),
                "item": line.item,
                "status": line.status.as_str(),
                "source": line.source,
                "required_before_default": line.required_before_default,
            }))
            .collect::<Vec<_>>(),
        "restore_gate": report.restore_gate,
    })
}

pub(super) fn kernel_program_fallback_retirement_gate_json(
    report: &KernelProgramFallbackRetirementGateReport,
) -> Value {
    json!({
        "schema": report.schema,
        "admitted": report.admitted,
        "default_switch_allowed": report.default_switch_allowed,
        "c_tproxy_object_retirement_allowed": report.c_tproxy_object_retirement_allowed,
        "c_trace_object_retirement_allowed": report.c_trace_object_retirement_allowed,
        "go_bpf_fallback_retirement_allowed": report.go_bpf_fallback_retirement_allowed,
        "tc_command_fallback_retirement_allowed": report.tc_command_fallback_retirement_allowed,
        "trace_diagnostic_retirement_allowed": report.trace_diagnostic_retirement_allowed,
        "c_tproxy_object_required": report.c_tproxy_object_required,
        "c_trace_object_required": report.c_trace_object_required,
        "go_bpf_fallback_required": report.go_bpf_fallback_required,
        "go_trace_fallback_required": report.go_trace_fallback_required,
        "tc_command_fallback_required": report.tc_command_fallback_required,
        "go_userspace_control_plane_preserved": report.go_userspace_control_plane_preserved,
        "retirement_scope": report.retirement_scope,
        "explicit_user_approval_recorded": report.explicit_user_approval_recorded,
        "product_chain_recertified": report.product_chain_recertified,
        "blockers": report
            .blockers
            .iter()
            .map(|blocker| blocker.as_str())
            .collect::<Vec<_>>(),
        "missing_parity_checks": report
            .missing_parity_checks
            .iter()
            .map(|check| check.as_str())
            .collect::<Vec<_>>(),
        "trace_restore_gate": report.trace_restore_gate,
    })
}

pub(super) fn native_backend_admission_json(report: &NativeBackendAdmissionReport) -> Value {
    json!({
        "schema": report.schema,
        "report_only": report.report_only,
        "admitted": report.admitted,
        "default_enable_allowed": report.default_enable_allowed,
        "selected_native_backend": attach_backend_value(report.selected_native_backend),
        "fallback_required": report.fallback_required,
        "tcx_optional_smoke": report.tcx_optional_smoke.as_str(),
        "required_checks": report
            .required_checks
            .iter()
            .map(|check| check.as_str())
            .collect::<Vec<_>>(),
        "missing_checks": report
            .missing_checks
            .iter()
            .map(|check| check.as_str())
            .collect::<Vec<_>>(),
        "failed_optional_checks": report.failed_optional_checks,
    })
}

pub(super) fn attach_backend_value(backend: Option<AttachBackend>) -> Value {
    backend
        .map(|backend| json!(backend.as_str()))
        .unwrap_or(Value::Null)
}

pub(super) fn loader_backend_str(backend: LoaderBackend) -> &'static str {
    backend.as_str()
}
