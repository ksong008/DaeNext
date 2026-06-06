use crate::*;

fn opt_in_request(
    opt_in_enabled: bool,
    requested_backend: AttachBackend,
    evidence: NativeBackendAdmissionEvidence,
) -> NativeBackendOptInRequest {
    NativeBackendOptInRequest {
        opt_in_enabled,
        requested_backend,
        admission_report: native_backend_admission_report(evidence, false),
        native_loader_available: true,
        tc_command_fallback_available: true,
    }
}

#[test]
fn native_backend_opt_in_default_is_fallback_only() {
    let admission =
        native_backend_admission_report(NativeBackendAdmissionEvidence::report_only(), true);
    let decision =
        native_backend_opt_in_decision(NativeBackendOptInRequest::report_only(admission));
    assert_eq!(decision.schema, "native-ebpf-backend-opt-in");
    assert!(!decision.opt_in_enabled);
    assert_eq!(decision.requested_backend, AttachBackend::Auto);
    assert!(!decision.admission_admitted);
    assert_eq!(
        decision.native_loader_available,
        cfg!(feature = "aya-loader")
    );
    assert!(!decision.attempt_native_backend);
    assert_eq!(
        decision.selected_backend,
        Some(AttachBackend::TcCommandFallback)
    );
    assert_eq!(decision.native_backend_candidate, None);
    assert_eq!(
        decision.fallback_backend,
        Some(AttachBackend::TcCommandFallback)
    );
    assert!(decision.fallback_required);
    assert!(decision.fallback_preserved);
    assert!(!decision.default_enable_allowed);
    assert_eq!(decision.reason, NativeBackendOptInReason::NotOptedIn);
}

#[test]
fn native_backend_opt_in_blocks_when_admission_missing() {
    let decision = native_backend_opt_in_decision(opt_in_request(
        true,
        AttachBackend::Auto,
        NativeBackendAdmissionEvidence::report_only(),
    ));
    assert!(decision.opt_in_enabled);
    assert!(!decision.admission_admitted);
    assert!(!decision.attempt_native_backend);
    assert_eq!(
        decision.selected_backend,
        Some(AttachBackend::TcCommandFallback)
    );
    assert_eq!(decision.reason, NativeBackendOptInReason::AdmissionNotMet);
}

#[test]
fn native_backend_opt_in_blocks_when_loader_is_unavailable() {
    let request = NativeBackendOptInRequest {
        opt_in_enabled: true,
        requested_backend: AttachBackend::Auto,
        admission_report: native_backend_admission_report(
            NativeBackendAdmissionEvidence::completed_a3_local(),
            false,
        ),
        native_loader_available: false,
        tc_command_fallback_available: true,
    };
    let decision = native_backend_opt_in_decision(request);
    assert!(decision.admission_admitted);
    assert!(!decision.native_loader_available);
    assert!(!decision.attempt_native_backend);
    assert_eq!(
        decision.selected_backend,
        Some(AttachBackend::TcCommandFallback)
    );
    assert_eq!(
        decision.reason,
        NativeBackendOptInReason::NativeLoaderUnavailable
    );
}

#[test]
fn native_backend_opt_in_auto_uses_admitted_tcx_candidate() {
    let decision = native_backend_opt_in_decision(opt_in_request(
        true,
        AttachBackend::Auto,
        NativeBackendAdmissionEvidence::completed_a3_local(),
    ));
    assert!(decision.admission_admitted);
    assert!(decision.attempt_native_backend);
    assert_eq!(decision.selected_backend, Some(AttachBackend::Tcx));
    assert_eq!(decision.native_backend_candidate, Some(AttachBackend::Tcx));
    assert_eq!(
        decision.fallback_backend,
        Some(AttachBackend::TcCommandFallback)
    );
    assert!(decision.fallback_required);
    assert!(decision.fallback_preserved);
    assert!(!decision.default_enable_allowed);
    assert_eq!(
        decision.reason,
        NativeBackendOptInReason::NativeBackendCandidateSelected
    );
}

#[test]
fn native_backend_opt_in_explicit_tc_netlink_is_allowed_after_a3() {
    let decision = native_backend_opt_in_decision(opt_in_request(
        true,
        AttachBackend::TcNetlink,
        NativeBackendAdmissionEvidence::completed_a3_local(),
    ));
    assert!(decision.attempt_native_backend);
    assert_eq!(decision.selected_backend, Some(AttachBackend::TcNetlink));
    assert_eq!(
        decision.native_backend_candidate,
        Some(AttachBackend::TcNetlink)
    );
}

#[test]
fn native_backend_opt_in_explicit_tcx_fails_closed_without_tcx_evidence() {
    let mut evidence = NativeBackendAdmissionEvidence::completed_a3_local();
    evidence.tcx_optional_smoke = OptionalAdmissionEvidence::NotRequired;
    let decision =
        native_backend_opt_in_decision(opt_in_request(true, AttachBackend::Tcx, evidence));
    assert!(decision.admission_admitted);
    assert!(!decision.attempt_native_backend);
    assert_eq!(
        decision.selected_backend,
        Some(AttachBackend::TcCommandFallback)
    );
    assert_eq!(decision.native_backend_candidate, None);
    assert_eq!(
        decision.reason,
        NativeBackendOptInReason::RequestedNativeBackendUnavailable
    );
}

#[test]
fn native_backend_opt_in_fails_closed_when_fallback_is_missing() {
    let request = NativeBackendOptInRequest {
        opt_in_enabled: true,
        requested_backend: AttachBackend::Auto,
        admission_report: native_backend_admission_report(
            NativeBackendAdmissionEvidence::completed_a3_local(),
            false,
        ),
        native_loader_available: true,
        tc_command_fallback_available: false,
    };
    let decision = native_backend_opt_in_decision(request);
    assert!(decision.admission_admitted);
    assert!(!decision.attempt_native_backend);
    assert_eq!(decision.selected_backend, None);
    assert_eq!(decision.fallback_backend, None);
    assert!(decision.fallback_required);
    assert!(!decision.fallback_preserved);
    assert_eq!(
        decision.reason,
        NativeBackendOptInReason::FallbackUnavailable
    );
}
