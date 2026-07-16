use super::*;

#[test]
fn every_direct_classification_selector_has_a_builder_and_ownership_witness() {
    assert_direct_classification_witnesses(
        "legacy-layer-shape",
        legacy_vmess_classification_sources(),
    );
    assert_direct_classification_witnesses(
        "xhttp-extended-settings-wrapper",
        ["http/1.1", "h2", "h3"].map(|alpn| {
            vless_xhttp_parser_fixture_url("packet-up", alpn, r#"{"headers":{"X-Test":"alpha"}}"#)
        }),
    );
}

#[test]
fn chained_legacy_vmess_sources_match_the_declared_parent_scheme_union() {
    let legacy = vmess_legacy_fixture_url();
    let socks5 = socks5_fixture_url(&fixture_host(FixtureEndpoint::Secondary), fixture_port(9));
    let socks = socks5.replacen("socks5://", "socks://", 1);
    let http = http_proxy_fixture_url(&fixture_host(FixtureEndpoint::Secondary), fixture_port(9));
    let row = dae_outbound::source_shape_registry_rows()
        .iter()
        .find(|row| row.shape_id == "legacy-layer-shape")
        .unwrap();

    assert_eq!(row.link_schemes, &["vmess", "socks", "socks5", "http"]);
    for parent in [socks, socks5, http] {
        let source = format!("{parent} -> {legacy}");
        let proxy = build_resident_proxy_plan_for_node(
            &fixture_config(),
            "proxy".to_owned(),
            "classified-source".to_owned(),
            source.clone(),
        )
        .unwrap_or_else(|error| panic!("build chained legacy VMess {source}: {error}"));
        assert!(source_shape_classifies_materialization(
            row, &proxy, &source
        ));
    }
}

fn assert_direct_classification_witnesses(
    shape_id: &str,
    sources: impl IntoIterator<Item = String>,
) {
    let reconciliation = source_shape_reconciliation(shape_id).unwrap();
    let row = dae_outbound::source_shape_registry_rows()
        .iter()
        .find(|row| row.shape_id == shape_id)
        .unwrap();
    let mut witnessed = vec![false; reconciliation.classification_selectors.len()];

    for source in sources {
        let proxy = build_resident_proxy_plan_for_node(
            &fixture_config(),
            "proxy".to_owned(),
            "classified-source".to_owned(),
            source.clone(),
        )
        .unwrap_or_else(|error| panic!("build {shape_id} source: {error}"));
        let shape = materialized_source_shape(&proxy, &source);
        let mut matched = false;
        for (index, selector) in reconciliation.classification_selectors.iter().enumerate() {
            if selector.matches(shape) {
                witnessed[index] = true;
                matched = true;
            }
        }
        assert!(matched, "{shape_id}: {shape:?}");
        let runtime_model = materialized_source_runtime_ownership_model(&proxy);
        assert_eq!(shape.runtime_ownership_model(), runtime_model, "{shape_id}");
        assert!(
            row.runtime_ownership.accepts_materialized(runtime_model),
            "{shape_id}: {}",
            runtime_model.as_report_str()
        );
        assert!(source_shape_classifies_materialization(
            row, &proxy, &source
        ));
    }

    assert!(
        witnessed.iter().all(|witnessed| *witnessed),
        "{shape_id} missing direct classifier witnesses: {witnessed:?}"
    );
}

fn legacy_vmess_classification_sources() -> Vec<String> {
    let plain = vmess_legacy_fixture_url();
    let tls = |wrapper: &str| {
        plain
            .replace("obfs=tcp", &format!("obfs={wrapper}"))
            .replace("?alterId=0", "?alterId=0&tls=1")
    };
    let plain_wrapper = |wrapper: &str| plain.replace("obfs=tcp", &format!("obfs={wrapper}"));
    let parent = socks5_fixture_url(&fixture_host(FixtureEndpoint::Secondary), fixture_port(9));

    vec![
        plain.clone(),
        tls("tcp"),
        plain_wrapper("websocket"),
        tls("websocket"),
        plain_wrapper("httpupgrade"),
        tls("httpupgrade"),
        tls("grpc"),
        tls("h2"),
        format!("{parent} -> {plain}"),
        format!("{parent} -> {}", plain_wrapper("websocket")),
        format!("{parent} -> {}", plain_wrapper("httpupgrade")),
    ]
}
