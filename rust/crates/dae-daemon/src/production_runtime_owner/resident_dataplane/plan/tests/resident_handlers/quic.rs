use super::*;
pub(super) fn assert_quic_handlers(config: &Config) -> Vec<ResidentProxyPlan> {
    let hysteria2 = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "hy2_live".to_owned(),
        hysteria2_fixture_url("hy2", "203.0.113.10", 28453),
    )
    .unwrap();
    assert_eq!(hysteria2.protocol, "hysteria2");
    assert_eq!(hysteria2.server_host, "203.0.113.10");
    assert_eq!(hysteria2.server_port, 28453);
    assert_eq!(hysteria2.server_name, "office.example");
    assert_eq!(hysteria2.net, "udp");
    assert_eq!(hysteria2.tls, "quic");
    assert!(matches!(
        hysteria2.handler,
        ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. }
    ));

    let hysteria2_hopping = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "hy2_hopping_live".to_owned(),
        hysteria2_fixture_url_with_pin("hy2", "203.0.113.10:28453,28454-28455", "AA-BB-CC"),
    )
    .unwrap();
    assert_eq!(hysteria2_hopping.protocol, "hysteria2");
    assert_eq!(hysteria2_hopping.server_host, "203.0.113.10");
    assert_eq!(hysteria2_hopping.server_port, 28453);
    assert!(matches!(
        hysteria2_hopping.handler,
        ResidentProxyProtocolPlan::Hysteria2QuicTcp {
            ref port_hop_ports,
            ..
        } if port_hop_ports == &vec![28453, 28454, 28455]
    ));

    let tuic = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "tuic_live".to_owned(),
        tuic_fixture_url("tuic", "203.0.113.10", 28454, true),
    )
    .unwrap();
    assert_eq!(tuic.protocol, "tuic");
    assert_eq!(tuic.server_host, "203.0.113.10");
    assert_eq!(tuic.server_port, 28454);
    assert_eq!(tuic.server_name, "office.example");
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
        tuic_fixture_url("tuic", "203.0.113.10", 28454, false),
    )
    .unwrap();
    assert_eq!(tuic_verified.protocol, "tuic");
    assert_eq!(tuic_verified.server_name, "office.example");
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
        juicity_fixture_url("juicity", "203.0.113.10", 28455, true),
    )
    .unwrap();
    assert_eq!(juicity.protocol, "juicity");
    assert_eq!(juicity.server_host, "203.0.113.10");
    assert_eq!(juicity.server_port, 28455);
    assert_eq!(juicity.server_name, "office.example");
    assert_eq!(juicity.net, "udp");
    assert_eq!(juicity.tls, "quic");
    assert!(matches!(
        juicity.handler,
        ResidentProxyProtocolPlan::JuicityQuicTcp { .. }
    ));
    vec![hysteria2, tuic, juicity]
}
