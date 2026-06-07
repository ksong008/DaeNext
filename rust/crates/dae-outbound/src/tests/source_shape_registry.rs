use super::*;

#[test]
fn source_shape_registry_separates_open_registry_from_complete_matrix() {
    let contract = source_shape_registry_contract();

    assert_eq!(contract.schema, "outbound-source-shape-registry");
    assert_eq!(contract.schema_version, 1);
    assert!(contract.source_shape_registry_open);
    assert!(contract.expanded_source_matrix_open);
    assert!(!contract.expanded_source_matrix_complete);
    assert!(!contract.release_gate_may_use_current_config_matrix_as_source_matrix);
    assert!(contract.rows.len() >= 20);
    assert!(
        contract
            .scoped_expanded_source_matrix_evidence
            .release_gate_ready
    );
    assert_eq!(
        contract
            .scoped_expanded_source_matrix_evidence
            .excluded_stream_wrappers,
        &["xhttp"]
    );
}

#[test]
fn source_shape_registry_current_baseline_rows_follow_matrix_contract() {
    let rows = source_shape_registry_rows();
    let baseline_rows = rows
        .iter()
        .filter(|row| row.shape_id.starts_with("baseline-"))
        .filter(|row| row.resident_status == "admitted-baseline")
        .collect::<Vec<_>>();

    assert!(baseline_rows.len() >= 10);
    for row in baseline_rows {
        assert!(!row.protocol_family.is_empty(), "{}", row.shape_id);
        assert!(!row.link_schemes.is_empty(), "{}", row.shape_id);
        assert_eq!(row.source_support, "source-supported");
        assert_eq!(row.state_ledger.resident_graph, "admitted");
        assert_eq!(row.executor_proof.proof_state, "runtime-executable");
        assert!(!row.expanded_live_matrix.blocked_rows_reduce_pass_threshold);
        assert!(row.redacted_identity.starts_with("registry:"));
    }
}

#[test]
fn source_shape_registry_blocks_extension_shapes_with_stable_reason_ids() {
    let taxonomy = capability_reason_taxonomy();
    let rows = source_shape_registry_rows();
    let blocked = rows
        .iter()
        .filter(|row| row.resident_status == "blocked")
        .collect::<Vec<_>>();
    let blocked_shape_ids = blocked.iter().map(|row| row.shape_id).collect::<Vec<_>>();

    assert!(blocked_shape_ids.is_empty());
    for row in blocked {
        let blocker = row
            .blocker_id
            .unwrap_or_else(|| panic!("missing blocker for {}", row.shape_id));
        assert!(
            taxonomy.contains(&blocker),
            "unexpected blocker {blocker} on {}",
            row.shape_id
        );
        assert_eq!(row.state_ledger.resident_graph, "blocked");
        assert_eq!(
            row.executor_proof.proof_state,
            "descriptor-only-fail-closed"
        );
        assert_eq!(row.runtime_selection.selected_runtime_scope, "not-selected");
        assert!(!row.evidence_requirements.is_empty(), "{}", row.shape_id);
    }
}

#[test]
fn source_shape_registry_admitted_rows_are_runtime_executable_and_evidence_gated() {
    let rows = source_shape_registry_rows();
    let scoped_evidence = source_shape_registry_contract().scoped_expanded_source_matrix_evidence;

    for row in rows
        .iter()
        .filter(|row| row.source_support == "source-supported")
        .filter(|row| row.resident_status == "admitted-baseline")
    {
        assert_eq!(row.blocker_id, None, "{}", row.shape_id);
        assert_eq!(
            row.state_ledger.resident_graph, "admitted",
            "{}",
            row.shape_id
        );
        assert_eq!(
            row.executor_proof.proof_state, "runtime-executable",
            "{}",
            row.shape_id
        );
        assert_eq!(
            row.runtime_selection.selected_runtime_scope, "current-selected-resident-graph",
            "{}",
            row.shape_id
        );
        if scoped_evidence.opened_rows.contains(&row.shape_id) {
            assert_eq!(
                row.expanded_live_matrix.ledger_state, "scoped-live-host-evidence-ready",
                "{}",
                row.shape_id
            );
            assert!(row.release_gate.expanded_source_agrees, "{}", row.shape_id);
            assert!(row.release_gate.service_contract_agrees, "{}", row.shape_id);
            assert!(row.release_gate.rollback_artifact_ready, "{}", row.shape_id);
            assert!(!row.release_gate.c10_final_ready, "{}", row.shape_id);
        } else {
            assert_eq!(
                row.expanded_live_matrix.ledger_state, "pending-live-host-evidence",
                "{}",
                row.shape_id
            );
        }
        for required in ["large-page-live", "benchmark", "rollback"] {
            assert!(
                row.evidence_requirements.contains(&required),
                "{} missing {required}",
                row.shape_id
            );
        }
        assert!(
            row.redacted_identity.starts_with("registry:"),
            "{}",
            row.shape_id
        );
    }
}

#[test]
fn source_shape_registry_records_scoped_release_gate_evidence() {
    let evidence = source_shape_registry_contract().scoped_expanded_source_matrix_evidence;

    assert_eq!(evidence.schema, "scoped-expanded-source-evidence");
    assert_eq!(evidence.schema_version, 1);
    assert_eq!(evidence.scope_id, "excluded-stream-wrapper-scope");
    assert_eq!(
        evidence.source_scope,
        "remaining-expanded-source-closure-rows"
    );
    assert_eq!(evidence.evidence_host, "remote-38");
    assert_eq!(evidence.upstream_host, "jp");
    assert_eq!(evidence.row_count, 5);
    assert_eq!(evidence.pass_count, 5);
    assert!(evidence.all_pass);
    assert!(evidence.large_page_all_pass);
    assert!(evidence.proxy_evidence_all_pass);
    assert!(evidence.benchmark_evidence_ready);
    assert_eq!(
        evidence.benchmark_evidence_kind,
        "large-page-threshold-and-body-hash"
    );
    assert!(evidence.rollback_artifact_ready);
    assert!(evidence.rollback_artifact_executed);
    assert!(evidence.cleanup_evidence_ready);
    assert!(!evidence.raw_links_retained);
    assert!(!evidence.raw_bodies_retained);
    assert!(!evidence.raw_state_retained);
    assert!(evidence.release_gate_ready);
    for expected in [
        "secure-endpoint-capability",
        "nested-chain-shape",
        "plugin-wrapper-layer",
        "legacy-layer-shape",
        "stream-wrapper-meek",
    ] {
        assert!(evidence.opened_rows.contains(&expected), "{expected}");
    }
}

#[test]
fn source_shape_registry_rejects_foreign_or_fallback_shapes() {
    let rows = source_shape_registry_rows();
    for expected in [
        "foreign-abi-outbound-shape",
        "external-oracle-dependent-shape",
        "internal-fallback-dependent-shape",
    ] {
        let row = rows
            .iter()
            .find(|row| row.shape_id == expected)
            .unwrap_or_else(|| panic!("missing rejected row {expected}"));
        assert_eq!(row.source_support, "not-source-supported");
        assert_eq!(row.resident_status, "not-source-supported");
        assert_eq!(row.blocker_id, Some("unsupported-source-policy"));
        assert_eq!(row.parser_coverage, "rejected");
    }
}

#[test]
fn source_shape_registry_contains_no_runtime_version_suffix_labels() {
    let rendered = source_shape_registry_contract().to_value().to_string();
    let forbidden = ["-", "v", "1"].concat();
    assert!(
        !rendered.contains(&forbidden),
        "source shape registry must not expose runtime version suffix labels"
    );
}

#[test]
fn source_shape_registry_uses_protocol_generic_matrix_semantics() {
    let rendered = source_shape_registry_contract().to_value().to_string();
    let forbidden = [
        "matrix-",
        "://matrix",
        "/matrix-",
        "#matrix-",
        "tag=matrix-",
        "name=matrix-",
    ];

    for needle in forbidden {
        assert!(
            !rendered.contains(needle),
            "source shape registry must use protocol-generic matrix semantics, found {needle}"
        );
    }
}
