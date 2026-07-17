use super::*;

#[test]
fn builder_witnesses_xhttp_versions_without_promoting_extended_settings() {
    for (shape_id, alpn) in [
        ("xhttp-h1-wrapper", "http/1.1"),
        ("stream-wrapper-xhttp", "h2"),
        ("xhttp-h3-wrapper", "h3"),
    ] {
        assert_witness(
            shape_id,
            vless_xhttp_parser_fixture_url("packet-up", alpn, ""),
        );
    }

    let extended =
        vless_xhttp_parser_fixture_url("packet-up", "h2", r#"{"headers":{"X-Test":"alpha"}}"#);
    let proxy = build(&extended).unwrap();
    let materialized = materialized_source_shape(&proxy, &extended);
    assert_eq!(
        materialized.xhttp_settings,
        MaterializedXhttpSettings::Extended
    );
    let extended_contract = source_shape_reconciliation("xhttp-extended-settings-wrapper").unwrap();
    assert_eq!(
        extended_contract.kind,
        SourceShapeReconciliationKind::AggregateCapability
    );
    assert!(extended_contract.classifies(materialized));
    assert!(!extended_contract.matches(materialized));
    assert!(
        !source_shape_reconciliation("stream-wrapper-xhttp")
            .unwrap()
            .matches(materialized)
    );

    let default = vless_xhttp_parser_fixture_url("packet-up", "h2", "");
    let mut generated = build(&default).unwrap();
    generated.apply_runtime_generation(73);
    generated
        .xhttp_xmux
        .as_mut()
        .unwrap()
        .physical_connection_limit += 1;
    let materialized = materialized_source_shape(&generated, &default);
    assert_eq!(
        materialized.xhttp_settings,
        MaterializedXhttpSettings::Default
    );
    assert!(
        source_shape_reconciliation("stream-wrapper-xhttp")
            .unwrap()
            .matches(materialized)
    );
}
