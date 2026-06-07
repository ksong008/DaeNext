use super::*;

#[test]
fn stream_wrapper_capability_records_closed_matrix_state() {
    let contract = stream_wrapper_capability_contract();

    assert_eq!(contract.schema, "stream-wrapper-capability");
    assert_eq!(contract.schema_version, 1);
    assert!(contract.websocket_wss_loopback_ready);
    assert!(contract.resident_source_admission_ready);
    assert!(contract.expanded_stream_wrapper_complete);
}

#[test]
fn stream_wrapper_capability_rows_follow_matrix_contract() {
    for row in stream_wrapper_capability_rows() {
        match row.source_admission {
            "admitted" => {
                assert_eq!(row.status, "resident-live-final", "{}", row.wrapper_id);
                assert_eq!(row.blocker_id, None, "{}", row.wrapper_id);
                assert_eq!(
                    row.reload_cleanup, "drop-on-graph-diff-or-runtime-stop",
                    "{}",
                    row.wrapper_id
                );
                assert_ne!(row.provider, "pending", "{}", row.wrapper_id);
                assert_ne!(row.security_underlay, "pending", "{}", row.wrapper_id);
                assert_ne!(row.packet_semantics, "pending", "{}", row.wrapper_id);
                assert_eq!(
                    row.evidence_requirements,
                    &["large-page-live", "benchmark", "rollback"],
                    "{}",
                    row.wrapper_id
                );
            }
            "blocked" => {
                assert_eq!(row.status, "blocked", "{}", row.wrapper_id);
                assert!(row.blocker_id.is_some(), "{}", row.wrapper_id);
                assert_eq!(row.reload_cleanup, "pending", "{}", row.wrapper_id);
            }
            other => panic!("unexpected stream wrapper admission {other}"),
        }
    }
}

#[test]
fn stream_wrapper_capability_contains_no_runtime_version_suffix_labels() {
    let rendered = stream_wrapper_capability_contract().to_value().to_string();
    let forbidden = ["-", "v", "1"].concat();

    assert!(
        !rendered.contains(&forbidden),
        "stream wrapper capability must not expose runtime version suffix labels"
    );
}
