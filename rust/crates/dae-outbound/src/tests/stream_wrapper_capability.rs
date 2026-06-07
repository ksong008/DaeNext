use super::*;

#[test]
fn stream_wrapper_capability_records_websocket_live_final_but_not_expanded_complete() {
    let contract = stream_wrapper_capability_contract();

    assert_eq!(contract.schema, "stream-wrapper-capability");
    assert_eq!(contract.schema_version, 1);
    assert!(contract.websocket_wss_loopback_ready);
    assert!(contract.resident_source_admission_ready);
    assert!(!contract.expanded_stream_wrapper_complete);

    let websocket = contract
        .rows
        .iter()
        .find(|row| row.wrapper_id == "websocket-wss-first-row")
        .unwrap();
    assert_eq!(websocket.status, "resident-live-final");
    assert_eq!(websocket.source_admission, "admitted");
    assert_eq!(websocket.provider, "resident-websocket-binary-frame");
    assert_eq!(websocket.blocker_id, None);
}

#[test]
fn stream_wrapper_capability_records_httpupgrade_live_final_but_not_expanded_complete() {
    let row = stream_wrapper_capability_rows()
        .iter()
        .find(|row| row.wrapper_id == "httpupgrade-wrapper")
        .expect("missing HTTP Upgrade wrapper row");

    assert_eq!(row.status, "resident-live-final");
    assert_eq!(row.source_admission, "admitted");
    assert_eq!(row.provider, "resident-http-upgrade-stream");
    assert_eq!(row.blocker_id, None);
    assert_eq!(
        row.evidence_requirements,
        &["large-page-live", "benchmark", "rollback"]
    );
}

#[test]
fn stream_wrapper_capability_records_grpc_live_final_but_not_expanded_complete() {
    let row = stream_wrapper_capability_rows()
        .iter()
        .find(|row| row.wrapper_id == "grpc-wrapper")
        .expect("missing gRPC wrapper row");

    assert_eq!(row.status, "resident-live-final");
    assert_eq!(row.source_admission, "admitted");
    assert_eq!(row.provider, "resident-grpc-h2-stream");
    assert_eq!(row.blocker_id, None);
    assert_eq!(
        row.evidence_requirements,
        &["large-page-live", "benchmark", "rollback"]
    );
}

#[test]
fn stream_wrapper_capability_keeps_missing_runtime_wrappers_blocked() {
    for expected in ["meek-wrapper", "xhttp-wrapper"] {
        let row = stream_wrapper_capability_rows()
            .iter()
            .find(|row| row.wrapper_id == expected)
            .unwrap_or_else(|| panic!("missing wrapper row {expected}"));
        assert_eq!(row.status, "blocked");
        assert_eq!(row.blocker_id, Some("missing-stream-wrapper"));
        assert_eq!(row.source_admission, "blocked");
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
