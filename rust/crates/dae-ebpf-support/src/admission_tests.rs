use crate::*;

#[test]
fn report_only_native_backend_admission_keeps_fallback_required() {
    let report =
        native_backend_admission_report(NativeBackendAdmissionEvidence::report_only(), true);
    assert_eq!(report.schema, "native-ebpf-backend-admission-v1");
    assert!(report.report_only);
    assert!(!report.admitted);
    assert!(!report.default_enable_allowed);
    assert_eq!(report.selected_native_backend, None);
    assert!(report.fallback_required);
    assert_eq!(
        report.tcx_optional_smoke,
        OptionalAdmissionEvidence::Missing
    );
    assert_eq!(report.required_checks, native_backend_required_checks());
    assert!(
        report
            .missing_checks
            .contains(&NativeBackendAdmissionCheck::AyaUserspaceLoadSmoke)
    );
    assert!(
        report
            .missing_checks
            .contains(&NativeBackendAdmissionCheck::CgroupAttachSmoke)
    );
    assert!(
        !report
            .missing_checks
            .contains(&NativeBackendAdmissionCheck::GoFallbackPreserved)
    );
    assert_eq!(report.failed_optional_checks, vec!["tcx_optional_smoke"]);
}

#[test]
fn completed_a3_native_backend_admission_selects_tcx_but_not_default() {
    let report = native_backend_admission_report(
        NativeBackendAdmissionEvidence::completed_a3_local(),
        false,
    );
    assert!(!report.report_only);
    assert!(report.admitted);
    assert!(!report.default_enable_allowed);
    assert_eq!(report.selected_native_backend, Some(AttachBackend::Tcx));
    assert!(!report.fallback_required);
    assert!(report.missing_checks.is_empty());
    assert!(report.failed_optional_checks.is_empty());
}

#[test]
fn native_backend_admission_allows_tcx_not_required_fallback_to_tc_netlink() {
    let mut evidence = NativeBackendAdmissionEvidence::completed_a3_local();
    evidence.tcx_optional_smoke = OptionalAdmissionEvidence::NotRequired;
    let report = native_backend_admission_report(evidence, false);
    assert!(report.admitted);
    assert_eq!(
        report.selected_native_backend,
        Some(AttachBackend::TcNetlink)
    );
    assert!(report.failed_optional_checks.is_empty());
}

#[test]
fn native_backend_admission_blocks_missing_fallback_preservation() {
    let mut evidence = NativeBackendAdmissionEvidence::completed_a3_local();
    evidence.go_fallback_preserved = false;
    let report = native_backend_admission_report(evidence, false);
    assert!(!report.admitted);
    assert_eq!(report.selected_native_backend, None);
    assert!(report.fallback_required);
    assert_eq!(
        report.missing_checks,
        vec![NativeBackendAdmissionCheck::GoFallbackPreserved]
    );
}
