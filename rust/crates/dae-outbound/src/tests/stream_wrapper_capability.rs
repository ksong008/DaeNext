use super::*;

#[test]
fn stream_wrapper_capability_opens_websocket_loopback_but_not_source_admission() {
    let contract = stream_wrapper_capability_contract();

    assert_eq!(contract.schema, "stream-wrapper-capability");
    assert_eq!(contract.schema_version, 1);
    assert!(contract.websocket_wss_loopback_ready);
    assert!(!contract.resident_source_admission_ready);
    assert!(!contract.expanded_stream_wrapper_complete);

    let websocket = contract
        .rows
        .iter()
        .find(|row| row.wrapper_id == "websocket-wss-first-row")
        .unwrap();
    assert_eq!(websocket.status, "loopback-admitted");
    assert_eq!(
        websocket.source_admission,
        "blocked-until-resident-materialization"
    );
    assert_eq!(websocket.provider, "shared-websocket-frame-executor");
    assert_eq!(websocket.blocker_id, Some("missing-live-evidence"));
}

#[test]
fn stream_wrapper_capability_keeps_other_wrappers_blocked() {
    for expected in [
        "grpc-wrapper",
        "httpupgrade-wrapper",
        "meek-wrapper",
        "xhttp-wrapper",
    ] {
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
