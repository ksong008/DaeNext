use crate::*;

fn runtime_request(
    native_backend_requested: bool,
    requested_backend: AttachBackend,
    evidence: NativeBackendAdmissionEvidence,
) -> NativeBackendRuntimeRequest {
    NativeBackendRuntimeRequest {
        native_backend_requested,
        requested_backend,
        admission_report: native_backend_admission_report(evidence, false),
        native_loader_available: true,
        tc_command_available: true,
    }
}

#[test]
fn native_backend_runtime_without_request_uses_command_backend() {
    let admission =
        native_backend_admission_report(NativeBackendAdmissionEvidence::report_only(), true);
    let decision =
        native_backend_runtime_decision(NativeBackendRuntimeRequest::report_only(admission));
    assert_eq!(decision.schema, "native-ebpf-backend-runtime-decision");
    assert!(!decision.native_backend_requested);
    assert_eq!(decision.requested_backend, AttachBackend::Auto);
    assert!(!decision.admission_admitted);
    assert_eq!(
        decision.native_loader_available,
        cfg!(feature = "aya-loader")
    );
    assert!(!decision.attempt_native_backend);
    assert_eq!(decision.selected_backend, Some(AttachBackend::TcCommand));
    assert_eq!(decision.native_backend_candidate, None);
    assert_eq!(decision.command_backend, Some(AttachBackend::TcCommand));
    assert!(decision.command_backend_required);
    assert!(decision.command_backend_available);
    assert!(!decision.automatic_enable_allowed);
    assert_eq!(
        decision.reason,
        NativeBackendRuntimeReason::NativeBackendNotRequested
    );
}

#[test]
fn native_backend_runtime_blocks_when_admission_missing() {
    let decision = native_backend_runtime_decision(runtime_request(
        true,
        AttachBackend::Auto,
        NativeBackendAdmissionEvidence::report_only(),
    ));
    assert!(decision.native_backend_requested);
    assert!(!decision.admission_admitted);
    assert!(!decision.attempt_native_backend);
    assert_eq!(decision.selected_backend, Some(AttachBackend::TcCommand));
    assert_eq!(decision.reason, NativeBackendRuntimeReason::AdmissionNotMet);
}

#[test]
fn native_backend_runtime_blocks_when_loader_is_unavailable() {
    let request = NativeBackendRuntimeRequest {
        native_backend_requested: true,
        requested_backend: AttachBackend::Auto,
        admission_report: native_backend_admission_report(
            NativeBackendAdmissionEvidence::verified_local(),
            false,
        ),
        native_loader_available: false,
        tc_command_available: true,
    };
    let decision = native_backend_runtime_decision(request);
    assert!(decision.admission_admitted);
    assert!(!decision.native_loader_available);
    assert!(!decision.attempt_native_backend);
    assert_eq!(decision.selected_backend, Some(AttachBackend::TcCommand));
    assert_eq!(
        decision.reason,
        NativeBackendRuntimeReason::NativeLoaderUnavailable
    );
}

#[test]
fn native_backend_runtime_auto_uses_admitted_tcx_candidate() {
    let decision = native_backend_runtime_decision(runtime_request(
        true,
        AttachBackend::Auto,
        NativeBackendAdmissionEvidence::verified_local(),
    ));
    assert!(decision.admission_admitted);
    assert!(decision.attempt_native_backend);
    assert_eq!(decision.selected_backend, Some(AttachBackend::Tcx));
    assert_eq!(decision.native_backend_candidate, Some(AttachBackend::Tcx));
    assert_eq!(decision.command_backend, Some(AttachBackend::TcCommand));
    assert!(decision.command_backend_required);
    assert!(decision.command_backend_available);
    assert!(!decision.automatic_enable_allowed);
    assert_eq!(
        decision.reason,
        NativeBackendRuntimeReason::NativeBackendCandidateSelected
    );
}

#[test]
fn native_backend_runtime_explicit_tc_netlink_is_allowed_after_a3() {
    let decision = native_backend_runtime_decision(runtime_request(
        true,
        AttachBackend::TcNetlink,
        NativeBackendAdmissionEvidence::verified_local(),
    ));
    assert!(decision.attempt_native_backend);
    assert_eq!(decision.selected_backend, Some(AttachBackend::TcNetlink));
    assert_eq!(
        decision.native_backend_candidate,
        Some(AttachBackend::TcNetlink)
    );
}

#[test]
fn native_backend_runtime_explicit_tcx_fails_closed_without_tcx_evidence() {
    let mut evidence = NativeBackendAdmissionEvidence::verified_local();
    evidence.tcx_optional_smoke = OptionalAdmissionEvidence::NotRequired;
    let decision =
        native_backend_runtime_decision(runtime_request(true, AttachBackend::Tcx, evidence));
    assert!(decision.admission_admitted);
    assert!(!decision.attempt_native_backend);
    assert_eq!(decision.selected_backend, Some(AttachBackend::TcCommand));
    assert_eq!(decision.native_backend_candidate, None);
    assert_eq!(
        decision.reason,
        NativeBackendRuntimeReason::RequestedNativeBackendUnavailable
    );
}

#[test]
fn native_backend_runtime_fails_closed_when_command_backend_is_missing() {
    let request = NativeBackendRuntimeRequest {
        native_backend_requested: true,
        requested_backend: AttachBackend::Auto,
        admission_report: native_backend_admission_report(
            NativeBackendAdmissionEvidence::verified_local(),
            false,
        ),
        native_loader_available: true,
        tc_command_available: false,
    };
    let decision = native_backend_runtime_decision(request);
    assert!(decision.admission_admitted);
    assert!(!decision.attempt_native_backend);
    assert_eq!(decision.selected_backend, None);
    assert_eq!(decision.command_backend, None);
    assert!(decision.command_backend_required);
    assert!(!decision.command_backend_available);
    assert_eq!(
        decision.reason,
        NativeBackendRuntimeReason::CommandBackendUnavailable
    );
}
