use super::*;
pub(crate) fn insert_source_and_bpf_footer(
    report: &mut Map<String, Value>,
    context: &ReportValueContext,
) {
    report.insert(
        "source".to_owned(),
        json!([
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:Post-Stage196",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.2",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.3",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.4",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.8",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.3",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.7",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.4",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.5",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.6",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.7",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.8",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.9",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:21.10"
        ]),
    );
    report.insert("go_default_path_preserved".to_owned(), json!(true));
    report.insert("go_fallback_required".to_owned(), json!(true));
    let fallback_retirement_gate =
        &context.ebpf_capability_json["kernel_program_fallback_retirement_gate"];
    let tproxy_dataplane_admission = &context.ebpf_capability_json["tproxy_dataplane_admission"];
    let go_bpf_fallback_required = fallback_retirement_gate["go_bpf_fallback_required"]
        .as_bool()
        .unwrap_or(true);
    let go_bpf_fallback_retired = fallback_retirement_gate["go_bpf_fallback_retirement_allowed"]
        .as_bool()
        .unwrap_or(false);
    report.insert(
        "go_bpf_loader_retirement_candidate".to_owned(),
        json!(
            tproxy_dataplane_admission["go_bpf_loader_retirement_candidate"]
                .as_bool()
                .unwrap_or(false)
        ),
    );
    report.insert(
        "go_bpf_fallback_retirement_gate_admitted".to_owned(),
        json!(
            fallback_retirement_gate["admitted"]
                .as_bool()
                .unwrap_or(false)
        ),
    );
    report.insert(
        "go_bpf_fallback_retirement_scope".to_owned(),
        fallback_retirement_gate["retirement_scope"].clone(),
    );
    report.insert(
        "go_bpf_fallback_required".to_owned(),
        json!(go_bpf_fallback_required),
    );
    report.insert(
        "go_bpf_fallback_retired".to_owned(),
        json!(go_bpf_fallback_retired),
    );
}
