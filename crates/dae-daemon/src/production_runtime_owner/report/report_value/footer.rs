use super::*;
pub(crate) fn insert_source_and_bpf_footer(
    report: &mut Map<String, Value>,
    context: &ReportValueContext,
) {
    report.insert(
        "source".to_owned(),
        json!(["rust-native-production-runtime-owner"]),
    );
    let native_backend_admitted =
        context.ebpf_capability_json["native_backend_admission"]["admitted"]
            .as_bool()
            .unwrap_or(false);
    let native_attach_attempted =
        context.ebpf_capability_json["native_backend_runtime"]["native_attach_attempted"]
            .as_bool()
            .unwrap_or(false);
    report.insert(
        "rust_native_runtime_owned".to_owned(),
        json!(native_backend_admitted),
    );
    report.insert(
        "native_backend_admitted".to_owned(),
        json!(native_backend_admitted),
    );
    report.insert(
        "native_attach_attempted".to_owned(),
        json!(native_attach_attempted),
    );
}
