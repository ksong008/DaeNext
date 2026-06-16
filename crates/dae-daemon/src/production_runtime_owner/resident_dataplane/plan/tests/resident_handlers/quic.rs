use super::*;
pub(super) fn assert_quic_handlers(config: &Config) -> Vec<ResidentProxyPlan> {
    let primary_host = fixture_host(FixtureEndpoint::Primary);
    let authority_host = fixture_host(FixtureEndpoint::Authority);
    let hysteria2 = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "hy2_live".to_owned(),
        hysteria2_fixture_url("hy2", &primary_host, fixture_port(1)),
    )
    .unwrap();
    assert_eq!(hysteria2.protocol, "hysteria2");
    assert_eq!(hysteria2.server_host, primary_host);
    assert_eq!(hysteria2.server_port, fixture_port(1));
    assert_eq!(hysteria2.server_name, authority_host);
    assert_eq!(hysteria2.net, "udp");
    assert_eq!(hysteria2.tls, "quic");
    assert!(matches!(
        hysteria2.handler,
        ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. }
    ));

    let hysteria2_obfs = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "hy2_salamander_live".to_owned(),
        hysteria2_salamander_fixture_url(&primary_host, fixture_port(1)),
    )
    .unwrap();
    assert!(matches!(
        hysteria2_obfs.handler,
        ResidentProxyProtocolPlan::Hysteria2QuicTcp {
            ref obfs,
            ..
        } if obfs.is_salamander()
    ));

    let hysteria2_hopping = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "hy2_hopping_live".to_owned(),
        hysteria2_fixture_url_with_pin(
            "hy2",
            &fixture_hop_server(
                fixture_port(1),
                &format!(",{}-{}", fixture_port(2), fixture_port(3)),
            ),
            &fixture_pin_sha256(),
        ),
    )
    .unwrap();
    assert_eq!(hysteria2_hopping.protocol, "hysteria2");
    assert_eq!(hysteria2_hopping.server_host, primary_host);
    assert_eq!(hysteria2_hopping.server_port, fixture_port(1));
    assert!(matches!(
        hysteria2_hopping.handler,
        ResidentProxyProtocolPlan::Hysteria2QuicTcp {
            ref port_hop_ports,
            ..
        } if port_hop_ports == &vec![fixture_port(1), fixture_port(2), fixture_port(3)]
    ));

    let tuic = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "tuic_live".to_owned(),
        tuic_fixture_url("tuic", &primary_host, fixture_port(2), true),
    )
    .unwrap();
    assert_eq!(tuic.protocol, "tuic");
    assert_eq!(tuic.server_host, primary_host);
    assert_eq!(tuic.server_port, fixture_port(2));
    assert_eq!(tuic.server_name, authority_host);
    assert_eq!(tuic.net, "udp");
    assert_eq!(tuic.tls, "quic");
    assert!(tuic.allow_insecure);
    assert!(matches!(
        tuic.handler,
        ResidentProxyProtocolPlan::TuicQuicTcp {
            allow_insecure: true,
            ..
        }
    ));

    let tuic_verified = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "tuic_verified_live".to_owned(),
        tuic_fixture_url("tuic", &primary_host, fixture_port(2), false),
    )
    .unwrap();
    assert_eq!(tuic_verified.protocol, "tuic");
    assert_eq!(tuic_verified.server_name, authority_host);
    assert_eq!(tuic_verified.tls, "quic");
    assert!(!tuic_verified.allow_insecure);
    assert!(matches!(
        tuic_verified.handler,
        ResidentProxyProtocolPlan::TuicQuicTcp {
            allow_insecure: false,
            ..
        }
    ));
    assert_eq!(
        tuic_verified.executable_graph_value()["runtimeComponents"]["underlayFactory"]["verificationPolicy"],
        "system-roots"
    );

    let juicity = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "juicity_live".to_owned(),
        juicity_fixture_url("juicity", &primary_host, fixture_port(3), true),
    )
    .unwrap();
    assert_eq!(juicity.protocol, "juicity");
    assert_eq!(juicity.server_host, primary_host);
    assert_eq!(juicity.server_port, fixture_port(3));
    assert_eq!(juicity.server_name, authority_host);
    assert_eq!(juicity.net, "udp");
    assert_eq!(juicity.tls, "quic");
    assert!(matches!(
        juicity.handler,
        ResidentProxyProtocolPlan::JuicityQuicTcp { .. }
    ));
    vec![hysteria2, tuic, juicity]
}
