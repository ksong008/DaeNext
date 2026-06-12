use super::*;
#[test]
pub(super) fn resident_dataplane_plan_keeps_fixed_from_building_unselected_candidate() {
    let node_a = socks5_endpoint_fixture_url(FixtureEndpoint::Primary);
    let unsupported = vless_xhttp_parser_fixture_url("stream-up", "h2", "");
    let config_text = r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        node_a: '__NODE_A__'
        unsupported: '__UNSUPPORTED_SOURCE__'
        }
        group {
        proxy {
            filter: name(node_a, unsupported)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#
    .replace("__NODE_A__", &node_a)
    .replace("__UNSUPPORTED_SOURCE__", &unsupported);
    let config = parse_config(&config_text);
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    assert_eq!(group.candidate_count(), 2);
    assert_eq!(group.admitted_candidate_count(), 1);
    assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_a");
}

#[test]
pub(super) fn resident_dataplane_plan_does_not_fallback_unresolved_name_filter_to_static_ss_node() {
    let candidate = vless_xhttp_parser_fixture_url("stream-up", "h2", "");
    let shadowsocks_2022 = ShadowsocksLink {
        name: String::new(),
        server: fixture_host(FixtureEndpoint::Primary),
        port: fixture_port(1),
        password: psk_for_conf(default_shadowsocks_2022_conf()),
        cipher: default_shadowsocks_2022_conf().cipher.to_owned(),
        plugin: Sip003::default(),
        udp: true,
        protocol: "shadowsocks".to_owned(),
    }
    .export_url();
    let config_text = r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        _022: '__SHADOWSOCKS_2022_SOURCE__'
        candidate: '__CANDIDATE_SOURCE__'
        }
        group {
        proxy {
            filter: name(node_17)
            policy: fixed
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#
    .replace("__SHADOWSOCKS_2022_SOURCE__", &shadowsocks_2022)
    .replace("__CANDIDATE_SOURCE__", &candidate);
    let config = parse_config(&config_text);
    let err = build_resident_dataplane_plan(&config).unwrap_err();
    assert!(err.contains("cannot resolve group proxy name filter node(s): node_17"));
    assert!(!err.contains("parse VLESS node _022"));
}
