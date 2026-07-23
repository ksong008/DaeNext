use super::*;

fn source_registry_row<'a>(report: &'a Value, shape_id: &str) -> &'a Value {
    report["source_shape_registry_rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["shapeId"].as_str() == Some(shape_id))
        .unwrap_or_else(|| panic!("missing source registry row {shape_id}"))
}

fn reconciliation<'a>(report: &'a Value, shape_id: &str) -> &'a Value {
    &source_registry_row(report, shape_id)["sourceShapeReconciliation"]
}

fn protocol_variant<'a>(report: &'a Value, shape_id: &str) -> &'a Value {
    report["excluded_stream_wrapper_source_matrix_typed_report"]["protocol_variant_rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["variantId"].as_str() == Some(shape_id))
        .unwrap_or_else(|| panic!("missing protocol variant row {shape_id}"))
}

fn assert_empty_components(reconciliation: &Value) {
    assert!(
        reconciliation["componentShapeIds"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        reconciliation["aggregateComponents"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

fn assert_public_reconciliation_shapes(report: &Value) {
    let production = reconciliation(report, "baseline-aead-cipher-endpoint");
    assert_eq!(production["kind"], "production-witness");
    assert!(production["selectorCount"].as_u64().unwrap() > 0);
    assert_eq!(production["classificationSelectorCount"], 0);
    assert_empty_components(production);
    assert_eq!(production["contributesProductionWitness"], true);

    let aggregate = reconciliation(report, "tls-fragment-security-underlay");
    assert_eq!(aggregate["kind"], "aggregate-capability");
    assert_eq!(aggregate["selectorCount"], 0);
    assert_eq!(aggregate["classificationSelectorCount"], 0);
    assert!(
        !aggregate["componentShapeIds"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        aggregate["aggregateComponents"]
            .as_array()
            .is_some_and(|components| {
                !components.is_empty()
                    && components.iter().all(|component| {
                        component["shapeId"].is_string()
                            && component["projection"].as_str() == Some("tls-fragment")
                    })
            })
    );
    assert_eq!(aggregate["contributesProductionWitness"], false);

    let classified_aggregate = reconciliation(report, "xhttp-extended-settings-wrapper");
    assert_eq!(classified_aggregate["kind"], "aggregate-capability");
    assert_eq!(classified_aggregate["selectorCount"], 0);
    assert!(
        classified_aggregate["classificationSelectorCount"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_empty_components(classified_aggregate);
    assert_eq!(classified_aggregate["contributesProductionWitness"], false);

    let deferred = reconciliation(report, "legacy-layer-shape");
    assert_eq!(deferred["kind"], "deferred-capability");
    assert_eq!(deferred["selectorCount"], 0);
    assert_eq!(deferred["classificationSelectorCount"], 12);
    assert_eq!(deferred["materializedShapeCount"], 47);
    assert_eq!(
        deferred["runtimeOwnershipModels"],
        json!([
            "flow-stream-and-packet-session",
            "generation-owned-h2-transport"
        ])
    );
    assert_eq!(
        deferred["classificationSelectors"]
            .as_array()
            .unwrap()
            .len(),
        12
    );
    assert_empty_components(deferred);
    assert_eq!(deferred["contributesProductionWitness"], false);

    let source_rejected = reconciliation(report, "non-native-abi-outbound-shape");
    assert_eq!(source_rejected["kind"], "source-rejected");
    assert_eq!(source_rejected["selectorCount"], 0);
    assert_eq!(source_rejected["classificationSelectorCount"], 0);
    assert_empty_components(source_rejected);
    assert_eq!(source_rejected["contributesProductionWitness"], false);
}

fn assert_kind_aware_status_counts(report: &Value) {
    let status_counts = &report["expanded_source_matrix_status_counts"];
    assert_eq!(status_counts["aggregate-report-only"], 4);
    assert_eq!(status_counts["blocked-aggregate-report-only"], 1);
    assert_eq!(status_counts["blocked-deferred"], 3);
    assert_eq!(status_counts["not-source-supported"], 5);
    assert_eq!(status_counts["blocked"].as_u64().unwrap_or(0), 0);
    assert!(status_counts["admitted"].as_u64().unwrap() > 0);
    assert_eq!(
        status_counts["admitted"].as_u64().unwrap()
            + status_counts["aggregate-report-only"].as_u64().unwrap()
            + status_counts["blocked-aggregate-report-only"]
                .as_u64()
                .unwrap()
            + status_counts["blocked-deferred"].as_u64().unwrap()
            + status_counts["not-source-supported"].as_u64().unwrap(),
        report["source_shape_registry_row_count"].as_u64().unwrap()
    );
    assert_eq!(
        report["expanded_source_matrix_runtime_blocked_row_count"],
        4
    );
    assert_eq!(
        report["expanded_source_matrix_policy_rejected_row_count"],
        5
    );

    let typed_counts = &report["expanded_source_matrix_typed_report"]["status_counts"];
    assert_eq!(typed_counts, status_counts);
    assert_eq!(typed_counts["aggregate-report-only"], 4);
    assert_eq!(typed_counts["blocked-aggregate-report-only"], 1);
    assert_eq!(typed_counts["blocked-deferred"], 3);
    assert_eq!(typed_counts["not-source-supported"], 5);
    assert_eq!(
        report["expanded_source_matrix_runtime_blocked_row_count"]
            .as_u64()
            .unwrap(),
        status_counts["blocked"].as_u64().unwrap_or(0)
            + status_counts["blocked-aggregate-report-only"]
                .as_u64()
                .unwrap()
            + status_counts["blocked-deferred"].as_u64().unwrap()
    );
}

fn assert_kind_aware_source_report(report: &Value) {
    let source_report = &report["excluded_stream_wrapper_source_matrix_typed_report"];
    assert_eq!(source_report["schemaVersion"], 2);
    assert!(
        source_report["source_supported_row_count"]
            .as_u64()
            .unwrap()
            > 20
    );
    assert_eq!(
        source_report["production_witness_row_count"],
        source_report["admitted_row_count"]
    );
    assert_eq!(source_report["aggregate_report_only_row_count"], 5);
    assert_eq!(source_report["resolved_aggregate_row_count"], 4);
    assert_eq!(source_report["unresolved_aggregate_row_count"], 1);
    assert_eq!(source_report["deferred_row_count"], 3);
    assert_eq!(source_report["missing_reconciliation_row_count"], 0);
    assert_eq!(source_report["explicit_fail_closed_row_count"], 3);
    assert!(
        source_report["all_production_witness_rows_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !source_report["all_aggregate_rows_resolved"]
            .as_bool()
            .unwrap()
    );
    assert!(!source_report["no_deferred_rows"].as_bool().unwrap());
    assert!(
        source_report["reconciliations_are_total"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !source_report["all_source_supported_rows_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!source_report["all_protocol_rows_open"].as_bool().unwrap());

    assert!(
        source_report["resolved_official_common_source_shape_count"]
            .as_u64()
            .unwrap()
            > source_report["admitted_official_common_source_shape_count"]
                .as_u64()
                .unwrap()
    );
    assert_eq!(
        source_report["aggregate_official_common_source_shape_count"],
        5
    );
    assert_eq!(
        source_report["deferred_official_common_source_shape_count"],
        3
    );
    assert!(
        !source_report["official_common_source_shapes_all_resolved"]
            .as_bool()
            .unwrap()
    );

    let blocked = source_report["blocked_protocol_variant_ids"]
        .as_array()
        .unwrap();
    for unresolved in [
        "legacy-layer-shape",
        "full-utls-security-underlay",
        "passthrough-udp-transport",
        "xhttp-extended-settings-wrapper",
    ] {
        assert!(
            blocked
                .iter()
                .any(|shape| shape.as_str() == Some(unresolved))
        );
    }
    assert_eq!(
        source_report["aggregate_shape_ids"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
    assert_eq!(
        source_report["unresolved_aggregate_shape_ids"],
        json!(["xhttp-extended-settings-wrapper"])
    );
    assert_eq!(
        source_report["deferred_shape_ids"],
        json!([
            "legacy-layer-shape",
            "full-utls-security-underlay",
            "passthrough-udp-transport"
        ])
    );
    assert!(
        source_report["missing_reconciliation_shape_ids"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let production = protocol_variant(report, "baseline-aead-2022-cipher-endpoint");
    assert_eq!(production["residentStatus"], "admitted-baseline");
    assert_eq!(production["reportStatus"], "admitted");
    assert_eq!(production["reconciliationKind"], "production-witness");
    assert_eq!(production["resolved"], true);
    assert_eq!(production["contributesProductionWitness"], true);

    let aggregate = protocol_variant(report, "tls-fragment-security-underlay");
    assert_eq!(aggregate["residentStatus"], "admitted-baseline");
    assert_eq!(aggregate["reportStatus"], "aggregate-report-only");
    assert_eq!(aggregate["reconciliationKind"], "aggregate-capability");
    assert_eq!(aggregate["resolved"], true);
    assert_eq!(aggregate["contributesProductionWitness"], false);

    let classified_aggregate = protocol_variant(report, "xhttp-extended-settings-wrapper");
    assert_eq!(classified_aggregate["residentStatus"], "blocked");
    assert_eq!(
        classified_aggregate["reportStatus"],
        "blocked-aggregate-report-only"
    );
    assert_eq!(
        classified_aggregate["reconciliationKind"],
        "aggregate-capability"
    );
    assert_eq!(classified_aggregate["resolved"], false);
    assert_eq!(classified_aggregate["contributesProductionWitness"], false);
    assert_eq!(
        classified_aggregate["blockerId"],
        "extended-xhttp-shape-not-exactly-classified"
    );

    let deferred = protocol_variant(report, "legacy-layer-shape");
    assert_eq!(deferred["residentStatus"], "blocked");
    assert_eq!(deferred["reportStatus"], "blocked-deferred");
    assert_eq!(deferred["securityUnderlay"], "plain-or-tls-stream-variants");
    assert_eq!(deferred["streamWrapper"], "none-or-stream-wrapper");
    assert_eq!(
        deferred["packetSemantics"],
        "udp-over-stream-or-protocol-closed"
    );
    assert_eq!(deferred["reconciliationKind"], "deferred-capability");
    assert_eq!(deferred["resolved"], false);
    assert_eq!(deferred["contributesProductionWitness"], false);
    assert_eq!(deferred["blockerId"], "legacy-vmess-wire-parity-not-proven");
}

pub(super) fn assert_source_reconciliation_contract(report: &Value) {
    assert_public_reconciliation_shapes(report);
    assert_kind_aware_status_counts(report);
    assert_kind_aware_source_report(report);
}
