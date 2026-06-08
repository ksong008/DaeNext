use super::*;
#[test]
pub(super) fn resident_dataplane_plan_selects_vless_group_node() {
    let source = vless_vision_fixture_url("");
    let config_source = r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: '__SOURCE__'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        pname(dae) -> must_direct
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#
    .replace("__SOURCE__", &source);
    let config = parse_config(&config_source);
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let proxy = plan.default_proxy_snapshot().unwrap();
    assert!(plan.enabled);
    assert_eq!(plan.proxies.len(), 1);
    assert_eq!(proxy.group_name, "proxy");
    assert_eq!(proxy.node_tag, "vless_live");
    assert_eq!(proxy.server_host, fixture_host(FixtureEndpoint::Primary));
    assert_eq!(proxy.server_port, fixture_authority_port());
    assert_eq!(proxy.server_name, fixture_host(FixtureEndpoint::Authority));
    assert_eq!(proxy.flow, "xtls-rprx-vision");
    assert_eq!(proxy.alpn, ["h2", "http/1.1"]);
    assert_eq!(proxy.mark, 1234);
}

#[test]
pub(super) fn group_node_selection_keeps_fixed_policy_order() {
    let node_a = socks5_endpoint_fixture_url(FixtureEndpoint::Primary);
    let node_b = socks5_endpoint_fixture_url(FixtureEndpoint::Secondary);
    let config_text = r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: '__NODE_A__'
        node_b: '__NODE_B__'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: fixed(1)
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#
    .replace("__NODE_A__", &node_a)
    .replace("__NODE_B__", &node_b);
    let config = parse_config(&config_text);
    let links = tagged_node_links(&config);
    let selected = select_group_nodes(&config.group[0], &links).unwrap();
    match selected {
        GroupNodeSelection::Selected(nodes) => {
            assert_eq!(nodes.len(), 2);
            assert_eq!(nodes[0].tag, "node_a");
            assert_eq!(nodes[0].link, node_a);
            assert_eq!(nodes[1].tag, "node_b");
            assert_eq!(nodes[1].link, node_b);
        }
        GroupNodeSelection::NoCandidate { .. } => panic!("expected selected node"),
    }
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let proxy = plan.default_proxy_snapshot().unwrap();
    assert_eq!(proxy.node_tag, "node_b");
    assert_eq!(plan.default_proxy_group().unwrap().candidate_count(), 2);
}

#[test]
pub(super) fn group_node_selection_supports_generic_name_filters() {
    let node_a = socks5_endpoint_fixture_url(FixtureEndpoint::Primary);
    let node_b = socks5_endpoint_fixture_url(FixtureEndpoint::Secondary);
    let node_c = socks5_endpoint_fixture_url(FixtureEndpoint::Tertiary);
    let config_text = r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: '__NODE_A__'
        node_b: '__NODE_B__'
        node_c: '__NODE_C__'
        }
        group {
        proxy {
            filter: name(regex: "^node_[ab]$") && !name(node_b)
            policy: random
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#
    .replace("__NODE_A__", &node_a)
    .replace("__NODE_B__", &node_b)
    .replace("__NODE_C__", &node_c);
    let config = parse_config(&config_text);
    let links = tagged_node_links(&config);
    let selected = select_group_nodes(&config.group[0], &links).unwrap();
    match selected {
        GroupNodeSelection::Selected(nodes) => {
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].tag, "node_a");
        }
        GroupNodeSelection::NoCandidate { .. } => panic!("expected selected node"),
    }
}

#[test]
pub(super) fn resident_dataplane_plan_keeps_non_fixed_group_candidates() {
    let node_a = socks5_endpoint_fixture_url(FixtureEndpoint::Primary);
    let node_b = socks5_endpoint_fixture_url(FixtureEndpoint::Secondary);
    let config_text = r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        node_a: '__NODE_A__'
        node_b: '__NODE_B__'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: random
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#
    .replace("__NODE_A__", &node_a)
    .replace("__NODE_B__", &node_b);
    let config = parse_config(&config_text);
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    assert_eq!(group.group_policy, ResidentGroupPolicyPlan::Random);
    assert_eq!(group.candidate_count(), 2);
    assert_eq!(group.admitted_candidate_count(), 2);
    assert!(group.alive_state_wired());
    let selected = group.select_proxy_for_tcp().unwrap();
    assert!(matches!(selected.node_tag.as_str(), "node_a" | "node_b"));
}

#[test]
pub(super) fn resident_dataplane_plan_wires_min_policy_latency_state() {
    let node_a = socks5_endpoint_fixture_url(FixtureEndpoint::Primary);
    let node_b = socks5_endpoint_fixture_url(FixtureEndpoint::Secondary);
    let config_text = r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        node_a: '__NODE_A__'
        node_b: '__NODE_B__'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: min_moving_avg
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#
    .replace("__NODE_A__", &node_a)
    .replace("__NODE_B__", &node_b);
    let config = parse_config(&config_text);
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    assert_eq!(
        group.group_policy,
        ResidentGroupPolicyPlan::MinMovingAverage
    );
    assert_eq!(group.candidate_count(), 2);
    assert_eq!(group.admitted_candidate_count(), 2);
    assert!(group.alive_state_wired());
    assert!(group.latency_state_wired());
    assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_a");
}
