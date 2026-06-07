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
}

#[test]
fn source_shape_registry_covers_current_baseline_handlers() {
    let rows = source_shape_registry_rows();

    for expected in [
        "shadowsocks",
        "trojan",
        "vmess",
        "vless",
        "hysteria2",
        "tuic",
        "juicity",
        "anytls",
        "http-proxy",
        "socks5",
    ] {
        let row = rows
            .iter()
            .find(|row| {
                row.protocol_family == expected && row.resident_status == "admitted-baseline"
            })
            .unwrap_or_else(|| panic!("missing admitted baseline row for {expected}"));
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

    assert!(blocked.len() >= 8);
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
        ["matrix", "-", "socks"].concat(),
        ["matrix", "-", "http"].concat(),
        ["matrix", "-", "ss"].concat(),
        ["matrix", "-", "shadowsocks"].concat(),
        ["matrix", "-", "trojan"].concat(),
        ["matrix", "-", "vmess"].concat(),
        ["matrix", "-", "vless"].concat(),
        ["matrix", "-", "anytls"].concat(),
        ["matrix", "-", "hy2"].concat(),
        ["matrix", "-", "hysteria"].concat(),
        ["matrix", "-", "tuic"].concat(),
        ["matrix", "-", "juicity"].concat(),
        ["socks5://", "matrix"].concat(),
        ["http://", "matrix"].concat(),
        ["trojan-go://", "matrix"].concat(),
        ["anytls://", "matrix"].concat(),
        ["/", "matrix", "-"].concat(),
        ["#", "matrix", "-"].concat(),
        ["tag=", "matrix", "-"].concat(),
        ["name=", "matrix", "-"].concat(),
    ];

    for needle in forbidden {
        assert!(
            !rendered.contains(&needle),
            "source shape registry must use protocol-generic matrix semantics, found {needle}"
        );
    }
}

#[test]
fn source_shape_registry_keeps_grpc_wrapper_fail_closed_until_runtime_proof() {
    let row = source_shape_registry_rows()
        .iter()
        .find(|row| row.shape_id == "stream-wrapper-grpc")
        .expect("missing gRPC stream-wrapper source row");

    assert_eq!(row.source_support, "source-supported");
    assert_eq!(row.resident_status, "blocked");
    assert_eq!(row.blocker_id, Some("missing-stream-wrapper"));
    assert_eq!(row.state_ledger.resident_graph, "blocked");
    assert_eq!(
        row.executor_proof.proof_state,
        "descriptor-only-fail-closed"
    );
    assert_eq!(row.runtime_selection.selected_runtime_scope, "not-selected");
    assert_eq!(row.expanded_live_matrix.ledger_state, "blocked-before-live");
    assert!(
        row.evidence_requirements
            .iter()
            .any(|requirement| *requirement == "large-page-live")
    );
}
