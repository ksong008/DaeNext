use super::*;

#[test]
fn outbound_production_matrix_contract_covers_current_native_handlers() {
    let contract = outbound_production_matrix_contract();
    assert_eq!(contract.schema, "outbound-production-matrix");
    assert!(contract.matrix_ready);
    assert!(contract.parser_export_metadata_ready);
    assert!(contract.tcp_udp_dataplane_ready);
    assert!(contract.transport_underlay_ready);
    assert!(contract.route_group_connectivity_ready);
    assert!(contract.reload_behavior_ready);
    assert!(contract.live_smoke_ready);
    assert!(contract.native_executor_matrix_ready);
    assert!(contract.source_registry_backed_ready);

    let handlers: Vec<_> = contract.entries.iter().map(|entry| entry.handler).collect();
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
        assert!(
            handlers.contains(&expected),
            "missing matrix entry: {expected}"
        );
    }

    for entry in contract.entries {
        assert!(entry.parser_export_metadata, "{}", entry.handler);
        assert!(entry.tcp_dataplane, "{}", entry.handler);
        assert!(entry.udp_dataplane, "{}", entry.handler);
        assert!(entry.transport_underlay, "{}", entry.handler);
        assert!(entry.route_group_connectivity, "{}", entry.handler);
        assert!(entry.reload_behavior, "{}", entry.handler);
        assert!(entry.live_smoke, "{}", entry.handler);
        assert!(entry.native_executor_ready, "{}", entry.handler);
        assert!(!entry.evidence.is_empty(), "{}", entry.handler);
        assert!(!entry.source_shape_ids.is_empty(), "{}", entry.handler);
    }
}

#[test]
fn outbound_production_matrix_ready_entries_are_backed_by_source_shapes() {
    let entries = production_matrix_entries();
    let rows = source_shape_registry_rows();
    assert!(production_matrix_entries_are_source_registry_backed(
        entries, rows
    ));

    for entry in entries {
        for shape_id in entry.source_shape_ids {
            let row = rows
                .iter()
                .find(|row| row.shape_id == *shape_id)
                .unwrap_or_else(|| {
                    panic!(
                        "{} references missing source-shape row {shape_id}",
                        entry.handler
                    )
                });
            assert_eq!(row.source_support, "source-supported", "{shape_id}");
            assert_eq!(row.resident_status, "admitted-baseline", "{shape_id}");
            assert_eq!(row.blocker_id, None, "{shape_id}");
            assert_eq!(
                row.executor_proof.proof_state, "runtime-executable",
                "{shape_id}"
            );
            assert!(row.typed_capability_contract().is_some(), "{shape_id}");
            assert!(
                row.security_underlay_policy_contract().is_some(),
                "{shape_id}"
            );
            assert_eq!(
                source_shape_reconciliation(shape_id)
                    .unwrap_or_else(|| panic!("missing reconciliation for {shape_id}"))
                    .kind,
                SourceShapeReconciliationKind::ProductionWitness,
                "aggregate or deferred row cannot back production matrix entry {shape_id}"
            );
        }
    }
}

#[test]
fn aggregate_and_deferred_rows_do_not_back_production_matrix_entries() {
    const AGGREGATE: &[&str] = &["quic-option-surface"];
    const DEFERRED: &[&str] = &["full-utls-security-underlay"];
    let baseline = production_matrix_entries()[0];
    let rows = source_shape_registry_rows();

    for source_shape_ids in [AGGREGATE, DEFERRED] {
        let entry = OutboundProductionMatrixEntry {
            source_shape_ids,
            ..baseline
        };
        assert!(
            !production_matrix_entries_are_source_registry_backed(&[entry], rows),
            "non-production reconciliation row backed production matrix entry {}",
            source_shape_ids[0]
        );
    }
}
