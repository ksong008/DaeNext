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

#[test]
fn ipv6_authority_keeps_socket_host_but_uses_unbracketed_tls_identity() {
    let proxy = build_resident_proxy_plan_for_node(
        &config_with_global_insecure(false),
        "proxy".to_owned(),
        "hysteria2_ipv6_identity".to_owned(),
        "hysteria2://auth@[2001:db8::1]:443#ipv6".to_owned(),
    )
    .unwrap();

    assert_eq!(proxy.server_host, "[2001:db8::1]");
    assert_eq!(proxy.server_name, "2001:db8::1");
    assert!(matches!(
        proxy.handler,
        ResidentProxyProtocolPlan::Hysteria2QuicTcp {
            ref tls_identity,
            ..
        } if tls_identity.server_name() == "2001:db8::1"
    ));
}

#[test]
fn explicit_hysteria2_sni_overrides_ipv6_authority_identity() {
    let proxy = build_resident_proxy_plan_for_node(
        &config_with_global_insecure(false),
        "proxy".to_owned(),
        "hysteria2_ipv6_sni".to_owned(),
        "hysteria2://auth@[2001:db8::1]:443?sni=server.example#ipv6-sni".to_owned(),
    )
    .unwrap();

    assert_eq!(proxy.server_host, "[2001:db8::1]");
    assert_eq!(proxy.server_name, "server.example");
    assert!(matches!(
        proxy.handler,
        ResidentProxyProtocolPlan::Hysteria2QuicTcp {
            ref tls_identity,
            ..
        } if tls_identity.server_name() == "server.example"
    ));
}

#[test]
fn absent_and_false_insecure_inputs_build_the_same_secure_pinned_policy() {
    let pin = fixture_pin_sha256();
    let absent = build_resident_proxy_plan_for_node(
        &config_with_global_insecure(false),
        "proxy".to_owned(),
        "hysteria2_absent_insecure".to_owned(),
        format!(
            "hysteria2://auth@{}?pinSHA256={pin}#secure",
            fixture_endpoint()
        ),
    )
    .unwrap();
    let explicit_false = build_resident_proxy_plan_for_node(
        &config_with_global_insecure(false),
        "proxy".to_owned(),
        "hysteria2_false_insecure".to_owned(),
        format!(
            "hysteria2://auth@{}?insecure=false&pinSHA256={pin}#secure",
            fixture_endpoint()
        ),
    )
    .unwrap();
    let ResidentProxyProtocolPlan::Hysteria2QuicTcp {
        tls_identity: absent_identity,
        ..
    } = absent.handler
    else {
        panic!("absent insecure fixture did not build Hysteria2");
    };
    let ResidentProxyProtocolPlan::Hysteria2QuicTcp {
        tls_identity: false_identity,
        ..
    } = explicit_false.handler
    else {
        panic!("explicit false fixture did not build Hysteria2");
    };

    assert_eq!(absent_identity, false_identity);
    assert!(absent_identity.policy().requires_webpki());
    assert!(absent_identity.policy().has_leaf_certificate_pin());
    assert!(!absent_identity.policy().allow_insecure());
}
