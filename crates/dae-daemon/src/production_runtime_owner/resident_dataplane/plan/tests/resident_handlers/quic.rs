use super::*;
pub(super) fn assert_quic_handlers(config: &Config) -> Vec<ResidentProxyPlan> {
    let primary_host = fixture_host(FixtureEndpoint::Primary);
    let authority_host = fixture_host(FixtureEndpoint::Authority);
    let hysteria2 = build_resident_proxy_plan_for_node(
        config,
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

    let hysteria2_insecure = build_resident_proxy_plan_for_node(
        config,
        "proxy".to_owned(),
        "hy2_insecure_live".to_owned(),
        hysteria2_insecure_fixture_url(&format!("{}:{}", primary_host, fixture_port(1))),
    )
    .unwrap();
    assert!(hysteria2_insecure.allow_insecure);
    assert!(matches!(
        hysteria2_insecure.handler,
        ResidentProxyProtocolPlan::Hysteria2QuicTcp {
            ref tls_identity,
            ..
        } if tls_identity.policy().allow_insecure()
            && !tls_identity.policy().has_leaf_certificate_pin()
    ));

    let hysteria2_obfs = build_resident_proxy_plan_for_node(
        config,
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
        config,
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
            port_hop_interval,
            ..
        } if port_hop_ports == &vec![fixture_port(1), fixture_port(2), fixture_port(3)]
            && port_hop_interval
                == Duration::from_nanos(config.global.udphop_interval.as_nanos() as u64)
    ));

    let tuic = build_resident_proxy_plan_for_node(
        config,
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
            udp_relay_mode: dae_outbound::tuic::TuicUdpRelayMode::Native,
            ..
        }
    ));

    let tuic_verified = build_resident_proxy_plan_for_node(
        config,
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
        config,
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
        ResidentProxyProtocolPlan::JuicityQuicTcp {
            congestion: dae_outbound::juicity::JuicityCongestionController::Bbr,
            ..
        }
    ));
    for proxy in [&hysteria2, &tuic] {
        let graph = proxy.executable_graph_value();
        assert_eq!(
            graph["runtimeComponents"]["underlayFactory"]["sessionPolicy"],
            serde_json::json!({
                "resumption": "quic-session-cache",
                "cacheScope": if cfg!(feature = "test-boringssl-quic") {
                    "reload-generation"
                } else {
                    "provider-config"
                },
                "zeroRtt": false,
            })
        );
        let lifecycle = &graph["runtimeComponents"]["underlayFactory"]["quicLifecycle"];
        assert_eq!(
            lifecycle["endpointScope"],
            "generation-graph-transport-owner"
        );
        assert_eq!(
            lifecycle["connectionScope"],
            "generation-graph-transport-owner"
        );
        assert_eq!(lifecycle["clientConfigScope"], "physical-transport-owner");
        assert_eq!(lifecycle["crossFlowConnectionReuse"], true);
        assert_eq!(
            graph["runtimeComponents"]["generationCache"]["perFlowProviders"],
            serde_json::json!([])
        );
        assert!(
            graph["runtimeComponents"]["generationCache"]["sharedProviderCaches"]
                .as_array()
                .unwrap()
                .iter()
                .any(|provider| provider == "quic-client-config")
        );
        assert_eq!(
            graph["runtimeComponents"]["generationCache"]["sharedProviderCaches"]
                .as_array()
                .unwrap()
                .iter()
                .any(|provider| provider == "quic-session-cache"),
            cfg!(feature = "test-boringssl-quic")
        );
    }

    let juicity_graph = juicity.executable_graph_value();
    assert_eq!(
        juicity_graph["runtimeComponents"]["underlayFactory"]["sessionPolicy"],
        serde_json::json!({
            "resumption": "quic-session-cache",
            "cacheScope": if cfg!(feature = "test-boringssl-quic") {
                "reload-generation"
            } else {
                "provider-config"
            },
            "zeroRtt": false,
        })
    );
    assert_eq!(
        juicity_graph["runtimeComponents"]["underlayFactory"]["congestionControl"],
        "bbr"
    );
    let juicity_lifecycle = &juicity_graph["runtimeComponents"]["underlayFactory"]["quicLifecycle"];
    assert_eq!(
        juicity_lifecycle["endpointScope"],
        "generation-graph-transport-owner"
    );
    assert_eq!(
        juicity_lifecycle["connectionScope"],
        "generation-graph-transport-owner"
    );
    assert_eq!(juicity_lifecycle["crossFlowConnectionReuse"], true);
    assert_eq!(
        juicity_graph["runtimeComponents"]["generationCache"]["perFlowProviders"],
        serde_json::json!([])
    );
    assert_eq!(
        juicity_graph["runtimeComponents"]["generationCache"]["sharedProviderCaches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|provider| provider == "quic-session-cache"),
        cfg!(feature = "test-boringssl-quic")
    );

    vec![hysteria2, tuic, juicity]
}

#[test]
fn juicity_congestion_controller_is_typed_and_partitions_graph_identity() {
    let config = resident_tcp_handler_config();
    let base = juicity_fixture_url(
        "juicity",
        &fixture_host(FixtureEndpoint::Primary),
        fixture_port(3),
        true,
    );
    let mut cubic_link = JuicityLink::parse(&base).unwrap();
    cubic_link.congestion_control = "cubic".to_owned();
    let cubic = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "juicity_cubic".to_owned(),
        cubic_link.export_url(),
    )
    .unwrap();
    let mut reno_link = JuicityLink::parse(&base).unwrap();
    reno_link.congestion_control = "new-reno".to_owned();
    let reno = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "juicity_reno".to_owned(),
        reno_link.export_url(),
    )
    .unwrap();

    assert!(matches!(
        cubic.handler,
        ResidentProxyProtocolPlan::JuicityQuicTcp {
            congestion: dae_outbound::juicity::JuicityCongestionController::Cubic,
            ..
        }
    ));
    assert!(matches!(
        reno.handler,
        ResidentProxyProtocolPlan::JuicityQuicTcp {
            congestion: dae_outbound::juicity::JuicityCongestionController::NewReno,
            ..
        }
    ));
    assert_ne!(cubic.graph_link_hash, reno.graph_link_hash);
    assert_eq!(
        cubic.executable_graph_value()["runtimeComponents"]["underlayFactory"]["congestionControl"],
        "cubic"
    );
    assert_eq!(
        reno.executable_graph_value()["runtimeComponents"]["underlayFactory"]["congestionControl"],
        "new_reno"
    );

    let mut invalid_link = JuicityLink::parse(&base).unwrap();
    invalid_link.congestion_control = "brutal".to_owned();
    let error = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "juicity_invalid".to_owned(),
        invalid_link.export_url(),
    )
    .unwrap_err();
    assert!(error.contains("validate Juicity congestion controller"));
    assert!(!error.contains("brutal"));
}

#[test]
fn tuic_stream_relay_mode_is_materialized_and_unknown_values_fail_closed() {
    let config = resident_tcp_handler_config();
    let mut link = TuicLink::parse(&tuic_fixture_url(
        "tuic",
        &fixture_host(FixtureEndpoint::Primary),
        fixture_port(2),
        false,
    ))
    .unwrap();

    link.udp_relay_mode = "quic".to_owned();
    let stream = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "tuic_stream_mode".to_owned(),
        link.export_url(),
    )
    .unwrap();
    assert!(matches!(
        stream.handler,
        ResidentProxyProtocolPlan::TuicQuicTcp {
            udp_relay_mode: dae_outbound::tuic::TuicUdpRelayMode::Quic,
            ..
        }
    ));
    let graph = stream.executable_graph_value();
    assert_eq!(graph["packetSemantics"], "quic-stream-packet");
    assert_eq!(
        graph["runtimeComponents"]["underlayFactory"]["tuicUdpRelayMode"],
        "quic"
    );
    assert_eq!(
        graph["runtimeComponents"]["udpExecutionAgreement"]["executor"],
        "resident-tuic-quic-unidirectional-stream-packet"
    );

    let private_mode = "private-relay-token";
    link.udp_relay_mode = private_mode.to_owned();
    let unknown_error = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "tuic_unknown_mode".to_owned(),
        link.export_url(),
    )
    .unwrap_err();
    assert!(unknown_error.contains("unsupported UDP relay mode"));
    assert!(!unknown_error.contains(private_mode));
}
