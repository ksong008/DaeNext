use super::*;
#[test]
pub(super) fn resident_dataplane_plan_selects_vless_group_node() {
    let config = parse_config(
        r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
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
        "#,
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let proxy = plan.default_proxy_snapshot().unwrap();
    assert!(plan.enabled);
    assert_eq!(plan.proxies.len(), 1);
    assert_eq!(proxy.group_name, "proxy");
    assert_eq!(proxy.node_tag, "vless_live");
    assert_eq!(proxy.server_host, "156.246.90.2");
    assert_eq!(proxy.server_port, 443);
    assert_eq!(proxy.server_name, "office.example");
    assert_eq!(proxy.flow, "xtls-rprx-vision");
    assert_eq!(proxy.alpn, ["h2", "http/1.1"]);
    assert_eq!(proxy.mark, 1234);
}

#[test]
pub(super) fn group_node_selection_keeps_fixed_policy_order() {
    let config = parse_config(
        r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
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
        "#,
    );
    let links = tagged_node_links(&config);
    let selected = select_group_nodes(&config.group[0], &links).unwrap();
    match selected {
        GroupNodeSelection::Selected(nodes) => {
            assert_eq!(nodes.len(), 2);
            assert_eq!(nodes[0].tag, "node_a");
            assert_eq!(nodes[0].link, "socks://127.0.0.1:1080");
            assert_eq!(nodes[1].tag, "node_b");
            assert_eq!(nodes[1].link, "socks://127.0.0.1:1081");
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
    let config = parse_config(
        r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        node_c: 'socks://127.0.0.1:1082'
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
        "#,
    );
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
    let config = parse_config(
        r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
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
        "#,
    );
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
    let config = parse_config(
        r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
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
        "#,
    );
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
