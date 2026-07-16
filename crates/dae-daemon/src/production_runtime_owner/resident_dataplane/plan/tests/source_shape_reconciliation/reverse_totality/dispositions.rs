use super::*;

#[test]
fn legacy_vmess_and_extended_xhttp_have_mechanical_non_production_dispositions() {
    let legacy = vmess_legacy_fixture_url();
    let legacy_proxy = build_plan(&legacy).unwrap();
    let legacy_shape = materialized_source_shape(&legacy_proxy, &legacy);
    assert!(production_match_ids(&legacy, &legacy_proxy).is_empty());
    let legacy_disposition = source_shape_reconciliation("legacy-layer-shape").unwrap();
    assert_eq!(
        legacy_disposition.kind,
        SourceShapeReconciliationKind::DeferredCapability
    );
    assert!(legacy_disposition.classifies(legacy_shape));

    for alpn in ["http/1.1", "h2", "h3"] {
        let source =
            vless_xhttp_parser_fixture_url("packet-up", alpn, r#"{"headers":{"X-Test":"alpha"}}"#);
        let proxy = build_plan(&source).unwrap_or_else(|error| panic!("xHTTP {alpn}: {error}"));
        let shape = materialized_source_shape(&proxy, &source);
        assert!(production_match_ids(&source, &proxy).is_empty(), "{alpn}");
        let disposition = source_shape_reconciliation("xhttp-extended-settings-wrapper").unwrap();
        assert_eq!(
            disposition.kind,
            SourceShapeReconciliationKind::AggregateCapability
        );
        assert!(disposition.classifies(shape), "{alpn}: {shape:?}");
        assert!(!disposition.contributes_production_witness());
    }
}

#[test]
fn chained_legacy_vmess_remains_deferred_for_every_admitted_plain_wrapper() {
    let legacy_tcp = vmess_legacy_fixture_url();
    let parent = socks5_fixture_url(&fixture_host(FixtureEndpoint::Secondary), fixture_port(9));
    let disposition = source_shape_reconciliation("legacy-layer-shape").unwrap();

    for (wrapper, child) in [
        ("tcp", legacy_tcp.clone()),
        (
            "websocket",
            legacy_tcp.replace("obfs=tcp", "obfs=websocket"),
        ),
        (
            "httpupgrade",
            legacy_tcp.replace("obfs=tcp", "obfs=httpupgrade"),
        ),
    ] {
        let source = format!("{parent} -> {child}");
        let proxy = build_plan(&source)
            .unwrap_or_else(|error| panic!("build chained legacy VMess {wrapper}: {error}"));
        let shape = materialized_source_shape(&proxy, &source);
        assert!(
            production_match_ids(&source, &proxy).is_empty(),
            "{wrapper}"
        );
        assert_eq!(shape.chain, dae_outbound::MaterializedChain::ParentConnect);
        assert_eq!(
            shape.chain_udp,
            dae_outbound::MaterializedChainUdp::ParentStream
        );
        assert_eq!(
            shape.source_import,
            dae_outbound::MaterializedSourceImport::LegacyVmess
        );
        assert!(disposition.classifies(shape), "{wrapper}: {shape:?}");
    }
}

#[test]
fn passthrough_requests_have_one_deferred_pre_materialization_disposition() {
    let mut source = url::Url::parse(&shadowsocks_fixture_url(
        "",
        &fixture_host(FixtureEndpoint::Primary),
        fixture_port(4),
    ))
    .unwrap();
    source.query_pairs_mut().append_pair(
        dae_outbound::shared_transport::contract::UDP_PASSTHROUGH_KEY,
        "true",
    );
    let error = build_plan(source.as_str()).unwrap_err();
    assert!(error.contains("fail-closed"));
    let disposition = source_shape_reconciliation("passthrough-udp-transport").unwrap();
    assert_eq!(
        disposition.kind,
        SourceShapeReconciliationKind::DeferredCapability
    );
    assert!(!disposition.contributes_production_witness());

    let parent = socks5_fixture_url(&fixture_host(FixtureEndpoint::Primary), fixture_port(5));
    let chain_error = build_plan(&format!("{parent} -> {source}")).unwrap_err();
    assert!(chain_error.contains("fail-closed"));
}

#[test]
fn policy_rejected_schemes_fail_before_materialization() {
    for (shape_id, source) in [
        ("non-native-abi-outbound-shape", "ffi://127.0.0.1:1"),
        (
            "external-runtime-dependent-shape",
            "foreign-runtime://127.0.0.1:1",
        ),
        (
            "non-native-executor-dependent-shape",
            "non-native-executor://127.0.0.1:1",
        ),
    ] {
        assert!(build_plan(source).is_err(), "{shape_id}");
        assert_eq!(
            source_shape_reconciliation(shape_id).unwrap().kind,
            SourceShapeReconciliationKind::SourceRejected,
            "{shape_id}"
        );
    }
}

fn build_plan(source: &str) -> Result<ResidentProxyPlan, String> {
    build_resident_proxy_plan_for_node(
        &fixture_config(),
        "proxy".to_owned(),
        "reverse-disposition".to_owned(),
        source.to_owned(),
    )
}
