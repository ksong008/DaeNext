use super::*;

pub(super) fn native_backend_admission_json(report: &NativeBackendAdmissionReport) -> Value {
    json!({
        "schema": report.schema,
        "report_only": report.report_only,
        "admitted": report.admitted,
        "automatic_enable_allowed": report.automatic_enable_allowed,
        "selected_native_backend": attach_backend_value(report.selected_native_backend),
        "command_backend_required": report.command_backend_required,
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
