use crate::*;

#[test]
fn report_only_native_backend_admission_requires_command_backend() {
    let report =
        native_backend_admission_report(NativeBackendAdmissionEvidence::report_only(), true);
    assert_eq!(report.schema, "native-ebpf-backend-admission");
    assert!(report.report_only);
    assert!(!report.admitted);
    assert!(!report.automatic_enable_allowed);
    assert_eq!(report.selected_native_backend, None);
    assert!(report.command_backend_required);
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
        !native_backend_required_checks()
            .iter()
            .any(|check| check.as_str().contains("external_bpf_dependency"))
    );
    assert_eq!(report.failed_optional_checks, vec!["tcx_optional_smoke"]);
}

#[test]
fn verified_local_native_backend_admission_selects_tcx_without_automatic_enable() {
    let report =
        native_backend_admission_report(NativeBackendAdmissionEvidence::verified_local(), false);
    assert!(!report.report_only);
    assert!(report.admitted);
    assert!(!report.automatic_enable_allowed);
    assert_eq!(report.selected_native_backend, Some(AttachBackend::Tcx));
    assert!(!report.command_backend_required);
    assert!(report.missing_checks.is_empty());
    assert!(report.failed_optional_checks.is_empty());
}

#[test]
fn native_backend_admission_allows_tcx_optional_tc_netlink() {
    let mut evidence = NativeBackendAdmissionEvidence::verified_local();
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
fn native_backend_admission_requires_native_object_default() {
    let mut evidence = NativeBackendAdmissionEvidence::verified_local();
    evidence.native_ebpf_object_default = false;
    let report = native_backend_admission_report(evidence, false);
    assert!(!report.admitted);
    assert!(report.command_backend_required);
    assert!(
        report
            .missing_checks
            .contains(&NativeBackendAdmissionCheck::NativeEbpfObjectDefault)
    );
}
