use super::*;

#[test]
fn registry_rows_and_reconciliations_are_total_and_unique() {
    let rows = source_shape_registry_rows();
    let reconciliations = source_shape_reconciliations();
    assert_eq!(rows.len(), 56);
    assert_eq!(rows.len(), reconciliations.len());

    for row in rows {
        assert_eq!(
            reconciliations
                .iter()
                .filter(|reconciliation| reconciliation.shape_id == row.shape_id)
                .count(),
            1,
            "{}",
            row.shape_id
        );
    }
    for reconciliation in reconciliations {
        assert_eq!(
            rows.iter()
                .filter(|row| row.shape_id == reconciliation.shape_id)
                .count(),
            1,
            "{}",
            reconciliation.shape_id
        );
    }

    let count = |kind| {
        reconciliations
            .iter()
            .filter(|reconciliation| reconciliation.kind == kind)
            .count()
    };
    assert_eq!(count(SourceShapeReconciliationKind::ProductionWitness), 43);
    assert_eq!(count(SourceShapeReconciliationKind::AggregateCapability), 5);
    assert_eq!(count(SourceShapeReconciliationKind::DeferredCapability), 3);
    assert_eq!(count(SourceShapeReconciliationKind::SourceRejected), 5);
}

#[test]
fn only_exact_materialized_rows_contribute_production_witnesses() {
    for reconciliation in source_shape_reconciliations() {
        match reconciliation.kind {
            SourceShapeReconciliationKind::ProductionWitness => {
                assert!(
                    !reconciliation.selectors.is_empty(),
                    "{}",
                    reconciliation.shape_id
                );
                assert!(reconciliation.classification_selectors.is_empty());
                assert!(reconciliation.aggregate_components.is_empty());
                assert!(reconciliation.contributes_production_witness());
            }
            SourceShapeReconciliationKind::AggregateCapability
            | SourceShapeReconciliationKind::DeferredCapability
            | SourceShapeReconciliationKind::SourceRejected => {
                assert!(
                    reconciliation.selectors.is_empty(),
                    "{}",
                    reconciliation.shape_id
                );
                assert!(!reconciliation.contributes_production_witness());
            }
        }
    }
}

#[test]
fn every_direct_selector_uses_an_accepted_runtime_ownership_model() {
    for reconciliation in source_shape_reconciliations() {
        let row = source_shape_registry_rows()
            .iter()
            .find(|row| row.shape_id == reconciliation.shape_id)
            .unwrap();
        for shape in reconciliation
            .selectors
            .iter()
            .chain(reconciliation.classification_selectors)
            .flat_map(|selector| selector.materialized_shapes())
        {
            let model = shape.runtime_ownership_model();
            assert!(
                row.runtime_ownership.accepts_materialized(model),
                "{} rejects {} for {shape:?}",
                reconciliation.shape_id,
                model.as_report_str()
            );
        }
    }
}

#[test]
fn production_selector_security_features_match_registry_policy() {
    for reconciliation in source_shape_reconciliations()
        .iter()
        .filter(|reconciliation| {
            reconciliation.kind == SourceShapeReconciliationKind::ProductionWitness
        })
    {
        let row = source_shape_registry_rows()
            .iter()
            .find(|row| row.shape_id == reconciliation.shape_id)
            .unwrap();
        let policy = row.security_underlay_policy_contract().unwrap();
        let variants = reconciliation
            .selectors
            .iter()
            .flat_map(|selector| selector.tls_variants.iter());
        let allow_insecure = variants
            .clone()
            .any(|variant| variant.features.allow_insecure)
            || reconciliation.selectors.iter().any(|selector| {
                selector
                    .quic_verification
                    .contains(&MaterializedQuicVerification::Insecure)
            });
        let fingerprint = variants.clone().any(|variant| variant.features.fingerprint);
        let fragment = variants.clone().any(|variant| variant.features.fragment);
        let reality = variants.clone().any(|variant| {
            matches!(
                variant.security,
                MaterializedSecurity::RealityRustls | MaterializedSecurity::RealityFingerprint
            )
        });

        assert_eq!(
            policy.allow_insecure_support, allow_insecure,
            "{} allow_insecure",
            reconciliation.shape_id
        );
        assert_eq!(
            policy.fingerprint_utls_support, fingerprint,
            "{} fingerprint",
            reconciliation.shape_id
        );
        assert_eq!(
            policy.tls_fragment_support, fragment,
            "{} fragment",
            reconciliation.shape_id
        );
        assert_eq!(
            policy.reality_support, reality,
            "{} reality",
            reconciliation.shape_id
        );
    }
}

#[test]
fn registry_display_strings_follow_exact_selector_roles() {
    for (shape_id, security, packet_semantics) in [
        (
            "connect-udp-h2-endpoint",
            "standard-or-insecure-tls",
            "connect-udp-capsule",
        ),
        (
            "baseline-tls-auth-endpoint",
            "tls-stream-variants",
            "udp-over-stream",
        ),
        (
            "baseline-aead-framed-endpoint",
            "plain-or-tls-stream-variants",
            "udp-over-stream",
        ),
        (
            "vless-native-tcp-endpoint",
            "plain-or-tls-stream-variants-or-reality",
            "udp-over-stream",
        ),
        (
            "stream-wrapper-websocket",
            "tls-stream-variants-or-reality",
            "udp-over-stream",
        ),
        (
            "stream-wrapper-grpc",
            "tls-stream-variants-or-reality",
            "udp-over-stream",
        ),
        (
            "stream-wrapper-httpupgrade",
            "tls-stream-variants-or-reality",
            "udp-over-stream",
        ),
        (
            "inner-encryption-stream-wrapper",
            "tls-stream-variants-without-fingerprint",
            "protocol-closed",
        ),
        (
            "tls-websocket-plugin-wrapper",
            "standard-or-fragmented-tls",
            "plugin-udp-policy-closed",
        ),
        (
            "proxy-transport-mode",
            "plain-or-tls-stream-variants",
            "protocol-closed",
        ),
        ("xhttp-h3-wrapper", "quic-tls", "udp-over-stream"),
    ] {
        let row = source_shape_registry_rows()
            .iter()
            .find(|row| row.shape_id == shape_id)
            .unwrap();
        assert_eq!(row.security_underlay, security, "{shape_id}");
        assert_eq!(row.packet_semantics, packet_semantics, "{shape_id}");
    }
}

#[test]
fn missing_source_provenance_and_wire_parity_remain_deferred() {
    for shape_id in [
        "legacy-layer-shape",
        "passthrough-udp-transport",
        "full-utls-security-underlay",
    ] {
        let row = source_shape_registry_rows()
            .iter()
            .find(|row| row.shape_id == shape_id)
            .unwrap();
        let reconciliation = source_shape_reconciliation(shape_id).unwrap();
        assert_eq!(row.resident_status, "blocked", "{shape_id}");
        assert_eq!(
            reconciliation.kind,
            SourceShapeReconciliationKind::DeferredCapability,
            "{shape_id}"
        );
        assert!(!reconciliation.contributes_production_witness());
    }
    assert!(!source_shape_registry_contract().expanded_source_matrix_complete);
}
