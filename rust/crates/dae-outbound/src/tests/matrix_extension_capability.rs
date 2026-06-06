use super::*;

#[test]
fn packet_semantics_capability_keeps_expanded_rows_fail_closed() {
    let contract = packet_semantics_capability_contract();

    assert_eq!(contract.schema, "packet-semantics-capability");
    assert_eq!(contract.schema_version, 1);
    assert!(contract.common_packet_semantics_ready);
    assert!(!contract.resident_source_admission_ready);
    assert!(!contract.expanded_packet_semantics_complete);

    let packet_transport = contract
        .rows
        .iter()
        .find(|row| row.semantics_id == "wrapper-packet-transport")
        .unwrap();
    assert_eq!(packet_transport.status, "blocked");
    assert_eq!(
        packet_transport.blocker_id,
        Some("missing-packet-semantics")
    );
    assert!(packet_transport.no_direct_fallback);
}

#[test]
fn extension_layer_capability_does_not_inherit_base_admission() {
    let contract = extension_layer_capability_contract();

    assert_eq!(contract.schema, "extension-layer-capability");
    assert_eq!(contract.schema_version, 1);
    assert!(contract.no_plugin_baseline_ready);
    assert!(!contract.plugin_wrapper_resident_source_admission_ready);
    assert!(!contract.legacy_layer_resident_source_admission_ready);
    assert!(!contract.expanded_extension_layer_complete);

    for expected in [
        "plugin-wrapper-layer",
        "legacy-cipher-layer",
        "legacy-obfs-layer",
    ] {
        let row = contract
            .rows
            .iter()
            .find(|row| row.layer_id == expected)
            .unwrap_or_else(|| panic!("missing extension layer row {expected}"));
        assert_eq!(row.status, "blocked");
        assert!(row.no_inherited_admission);
        assert!(row.blocker_id.is_some());
    }
}

#[test]
fn transport_option_capability_blocks_unproved_options() {
    let contract = transport_option_capability_contract();

    assert_eq!(contract.schema, "transport-option-capability");
    assert_eq!(contract.schema_version, 1);
    assert!(contract.baseline_transport_options_ready);
    assert!(!contract.quic_option_resident_source_admission_ready);
    assert!(!contract.secure_endpoint_resident_source_admission_ready);
    assert!(!contract.expanded_transport_option_complete);

    for expected in ["quic-option-surface", "secure-proxy-endpoint"] {
        let row = contract
            .rows
            .iter()
            .find(|row| row.option_id == expected)
            .unwrap_or_else(|| panic!("missing transport option row {expected}"));
        assert_eq!(row.status, "blocked");
        assert!(row.blocker_id.is_some());
        assert!(row.evidence_requirements.contains(&"large-page-live"));
        assert!(row.evidence_requirements.contains(&"rollback"));
    }
}

#[test]
fn expanded_live_matrix_validation_boundary_requires_remote_proxy_evidence() {
    let contract = expanded_live_matrix_validation_boundary_contract();

    assert_eq!(contract.schema, "expanded-live-matrix-validation-boundary");
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.evidence_host, "remote-38");
    assert_eq!(contract.upstream_host, "jp");
    assert!(contract.proxy_path_required);
    assert!(contract.direct_control_excluded);
    assert!(contract.benchmark_required);
    assert!(contract.rollback_artifact_required);
    assert!(!contract.blocked_rows_reduce_pass_threshold);
    assert!(!contract.expanded_live_matrix_complete);
    assert_eq!(contract.google_min_bytes, 10_000);
    assert_eq!(contract.youtube_min_bytes, 100_000);
}

#[test]
fn matrix_extension_capabilities_contain_no_runtime_version_suffix_labels() {
    let rendered = serde_json::json!({
        "packet": packet_semantics_capability_contract().to_value(),
        "extension": extension_layer_capability_contract().to_value(),
        "transport": transport_option_capability_contract().to_value(),
        "live": expanded_live_matrix_validation_boundary_contract().to_value(),
    })
    .to_string();
    let forbidden = ["-", "v", "1"].concat();

    assert!(
        !rendered.contains(&forbidden),
        "matrix extension capabilities must not expose runtime version suffix labels"
    );
}
