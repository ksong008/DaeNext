use super::*;

fn config_with_global_insecure(allow_insecure: bool) -> Config {
    parse_config(&format!(
        r#"
        global {{
        lan_interface: daerust0
        allow_insecure: {allow_insecure}
        so_mark_from_dae: 1234
        mptcp: false
        }}
        routing {{
        fallback: direct
        }}
        "#,
    ))
}

fn fixture_endpoint() -> String {
    format!(
        "{}:{}",
        fixture_host(FixtureEndpoint::Primary),
        fixture_port(1)
    )
}

#[test]
fn inherited_insecure_mode_preserves_the_node_certificate_pin() {
    let config = config_with_global_insecure(true);
    let proxy = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "hysteria2_inherited_insecure".to_owned(),
        hysteria2_fixture_url_with_pin("hy2", &fixture_endpoint(), &fixture_pin_sha256()),
    )
    .unwrap();
    assert!(matches!(
        proxy.handler,
        ResidentProxyProtocolPlan::Hysteria2QuicTcp {
            ref tls_identity,
            ..
        } if tls_identity.policy().allow_insecure()
            && tls_identity.policy().has_leaf_certificate_pin()
    ));
    assert_eq!(
        proxy.executable_graph_value()["runtimeComponents"]["underlayFactory"]["verificationPolicy"],
        "pinned-raw-cert-sha256"
    );
}

#[test]
fn malformed_certificate_pin_is_rejected_during_plan_construction() {
    let err = build_resident_proxy_plan_for_node(
        &config_with_global_insecure(false),
        "proxy".to_owned(),
        "hysteria2_bad_pin".to_owned(),
        hysteria2_fixture_url_with_pin("hy2", &fixture_endpoint(), "invalid-pin-value"),
    )
    .unwrap_err();
    assert!(err.contains("invalid Hysteria2 pinSHA256"));
    assert!(!err.contains("invalid-pin-value"));
}
