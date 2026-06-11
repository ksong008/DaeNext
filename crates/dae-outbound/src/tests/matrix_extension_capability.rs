use super::*;

#[test]
fn packet_semantics_capability_closes_non_xhttp_rows() {
    let contract = packet_semantics_capability_contract();

    assert_eq!(contract.schema, "packet-semantics-capability");
    assert_eq!(contract.schema_version, 1);
    assert!(contract.common_packet_semantics_ready);
    assert!(contract.resident_source_admission_ready);
    assert!(contract.expanded_packet_semantics_complete);

    for row in contract.rows {
        assert!(row.no_direct_alternate_path, "{}", row.semantics_id);
        assert_eq!(row.status, "admitted", "{}", row.semantics_id);
        assert_eq!(row.blocker_id, None, "{}", row.semantics_id);
        assert_eq!(row.reload_cleanup, "drop-on-graph-diff-or-runtime-stop");
    }
}

#[test]
fn extension_layer_capability_does_not_inherit_base_admission() {
    let contract = extension_layer_capability_contract();

    assert_eq!(contract.schema, "extension-layer-capability");
    assert_eq!(contract.schema_version, 1);
    assert!(contract.no_plugin_baseline_ready);
    assert!(contract.plugin_wrapper_resident_source_admission_ready);
    assert!(contract.legacy_layer_resident_source_admission_ready);
    assert!(contract.expanded_extension_layer_complete);

    for row in contract.rows {
        assert!(
            matches!(row.status, "admitted" | "fail-closed-final"),
            "{}",
            row.layer_id
        );
        assert_eq!(row.blocker_id, None, "{}", row.layer_id);
        assert_eq!(row.reload_cleanup, "drop-on-graph-diff-or-runtime-stop");
        assert!(row.no_inherited_admission, "{}", row.layer_id);
        if row.status == "fail-closed-final" {
            assert!(row.evidence_requirements.contains(&"negative-fixture"));
            assert!(
                row.evidence_requirements
                    .contains(&"no-direct-alternate-path")
            );
        }
    }
}

#[test]
fn transport_option_capability_closes_non_xhttp_rows() {
    let contract = transport_option_capability_contract();

    assert_eq!(contract.schema, "transport-option-capability");
    assert_eq!(contract.schema_version, 1);
    assert!(contract.baseline_transport_options_ready);
    assert!(contract.quic_option_resident_source_admission_ready);
    assert!(contract.secure_endpoint_resident_source_admission_ready);
    assert!(contract.expanded_transport_option_complete);

    for row in contract.rows {
        assert_eq!(row.status, "admitted", "{}", row.option_id);
        assert_eq!(row.blocker_id, None, "{}", row.option_id);
        assert_eq!(row.reload_cleanup, "drop-on-graph-diff-or-runtime-stop");
        if row.option_surface != "baseline" {
            assert!(row.evidence_requirements.contains(&"large-page-live"));
            assert!(row.evidence_requirements.contains(&"cleanup"));
        }
    }
}

#[test]
fn expanded_live_matrix_validation_boundary_requires_remote_proxy_evidence() {
    let contract = expanded_live_matrix_validation_boundary_contract();

    assert_eq!(contract.schema, "expanded-live-matrix-validation-boundary");
    assert_eq!(contract.schema_version, 1);
    assert_eq!(
        contract.validation_boundary,
        "external-client-through-resident-proxy"
    );
    assert_eq!(contract.upstream_boundary, "external-proxy-server-path");
    assert!(contract.proxy_path_required);
    assert!(contract.direct_control_excluded);
    assert!(contract.benchmark_required);
    assert!(contract.cleanup_artifact_required);
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
