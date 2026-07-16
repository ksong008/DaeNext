use super::*;

#[test]
fn legacy_import_stays_typed_and_deferred_after_builder_normalization() {
    let legacy = vmess_legacy_fixture_url();
    let proxy = build(&legacy).unwrap();
    let shape = materialized_source_shape(&proxy, &legacy);
    assert_eq!(shape.source_import, MaterializedSourceImport::LegacyVmess);
    assert!(
        !source_shape_reconciliation("baseline-aead-framed-endpoint")
            .unwrap()
            .matches(shape)
    );
    let legacy_reconciliation = source_shape_reconciliation("legacy-layer-shape").unwrap();
    assert_eq!(
        legacy_reconciliation.kind,
        SourceShapeReconciliationKind::DeferredCapability
    );
    assert!(legacy_reconciliation.classifies(shape));
    assert!(!legacy_reconciliation.matches(shape));
}

#[test]
fn passthrough_request_is_rejected_before_materialization() {
    let mut source = url::Url::parse(&shadowsocks_fixture_url(
        "",
        &fixture_host(FixtureEndpoint::Primary),
        fixture_port(2),
    ))
    .unwrap();
    source.query_pairs_mut().append_pair(
        dae_outbound::shared_transport::contract::UDP_PASSTHROUGH_KEY,
        "true",
    );
    let source = source.to_string();
    let error = build(&source).unwrap_err();
    assert!(error.contains(dae_outbound::shared_transport::contract::UDP_PASSTHROUGH_KEY));
    assert!(error.contains("fail-closed"));

    let passthrough = source_shape_reconciliation("passthrough-udp-transport").unwrap();
    assert_eq!(
        passthrough.kind,
        SourceShapeReconciliationKind::DeferredCapability
    );
    assert!(!passthrough.contributes_production_witness());
}

#[test]
fn production_rejected_sources_never_create_a_materialized_witness() {
    let mut vless_none_ws = VLESSLink::parse(&vless_plain_tcp_none_fixture_url()).unwrap();
    vless_none_ws.net = "ws".to_owned();
    vless_none_ws.host = fixture_host(FixtureEndpoint::Authority);
    vless_none_ws.path = "/ws".to_owned();

    let mut vless_reality_h2 = VLESSLink::parse(&vless_reality_fixture_url()).unwrap();
    vless_reality_h2.flow.clear();
    vless_reality_h2.net = "h2".to_owned();

    for link in [
        vless_none_ws.export_url(),
        vless_reality_h2.export_url(),
        vmess_fixture_url(
            "",
            &fixture_host(FixtureEndpoint::Primary),
            fixture_port(4),
            "h2",
            &fixture_host(FixtureEndpoint::Authority),
            "/h2",
            "none",
        ),
    ] {
        assert!(build(&link).is_err(), "unexpectedly materialized {link}");
    }
}

#[test]
fn source_rejected_rows_are_backed_by_builder_admission_failures() {
    let cases = [
        ("non-native-abi-outbound-shape", "ffi://127.0.0.1:1"),
        (
            "external-runtime-dependent-shape",
            "foreign-runtime://127.0.0.1:1",
        ),
        (
            "non-native-executor-dependent-shape",
            "non-native-executor://127.0.0.1:1",
        ),
    ];
    let rejected = dae_outbound::source_shape_reconciliations()
        .iter()
        .filter(|reconciliation| {
            reconciliation.kind == SourceShapeReconciliationKind::SourceRejected
        })
        .collect::<Vec<_>>();
    assert_eq!(rejected.len(), cases.len());
    for reconciliation in rejected {
        assert!(
            cases
                .iter()
                .any(|(shape_id, _)| *shape_id == reconciliation.shape_id),
            "source-rejected row lacks builder admission evidence: {}",
            reconciliation.shape_id
        );
    }
    for (shape_id, link) in cases {
        assert!(build(link).is_err(), "{shape_id}");
        assert_eq!(
            source_shape_reconciliation(shape_id).unwrap().kind,
            SourceShapeReconciliationKind::SourceRejected,
            "{shape_id}"
        );
    }
}
