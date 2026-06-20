use super::*;

fn two_node_latency_config(global_extra: &str, group_body: &str) -> Config {
    let node_a = socks5_endpoint_fixture_url(FixtureEndpoint::Primary);
    let node_b = socks5_endpoint_fixture_url(FixtureEndpoint::Secondary);
    let config_text = format!(
        r#"
        global {{
        lan_interface: daerust0
        {global_extra}
        }}
        node {{
        node_a: '{node_a}'
        node_b: '{node_b}'
        }}
        group {{
        proxy {{
            {group_body}
        }}
        }}
        routing {{
        l4proto(tcp) -> proxy
        fallback: direct
        }}
        "#
    );
    parse_config(&config_text)
}

#[test]
pub(super) fn resident_dataplane_min_policy_selects_checked_lowest_last_latency() {
    let config = two_node_latency_config(
        "",
        r#"
        filter: name(node_a, node_b)
        policy: min
        "#,
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    group
        .record_check_result("node_a", NetworkType::TCP4, Some(200), 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::TCP4, Some(50), 2)
        .unwrap();
    assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
}

#[test]
pub(super) fn resident_dataplane_min_avg10_policy_uses_latency_history() {
    let config = two_node_latency_config(
        "",
        r#"
        filter: name(node_a, node_b)
        policy: min_avg10
        "#,
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    for latency in [300, 300, 300] {
        group
            .record_check_result("node_a", NetworkType::TCP4, Some(latency), 1)
            .unwrap();
    }
    for latency in [120, 120, 120] {
        group
            .record_check_result("node_b", NetworkType::TCP4, Some(latency), 2)
            .unwrap();
    }
    assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
}

#[test]
pub(super) fn resident_dataplane_min_moving_avg_policy_uses_moving_average() {
    let config = two_node_latency_config(
        "",
        r#"
        filter: name(node_a, node_b)
        policy: min_moving_avg
        "#,
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    group
        .record_check_result("node_a", NetworkType::TCP4, Some(240), 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::TCP4, Some(80), 2)
        .unwrap();
    assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
}

#[test]
pub(super) fn resident_dataplane_min_policy_honors_group_check_tolerance() {
    let config = two_node_latency_config(
        "check_tolerance: 10ms",
        r#"
        filter: name(node_a, node_b)
        policy: min
        check_tolerance: 50ms
        "#,
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    group
        .record_check_result("node_a", NetworkType::TCP4, Some(100), 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::TCP4, Some(80), 2)
        .unwrap();
    assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_a");
    group
        .record_check_result("node_b", NetworkType::TCP4, Some(40), 3)
        .unwrap();
    assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
}

#[test]
pub(super) fn resident_dataplane_min_policy_applies_add_latency_to_sorting_only() {
    let config = two_node_latency_config(
        "",
        r#"
        filter: name(node_a) [add_latency: 100ms]
        filter: name(node_b)
        policy: min
        "#,
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    assert_eq!(group.annotation_latency_offset_count(), 1);
    group
        .record_check_result("node_a", NetworkType::TCP4, Some(50), 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::TCP4, Some(90), 2)
        .unwrap();
    assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
}

#[test]
pub(super) fn resident_dataplane_latency_policies_ignore_failed_manual_probe_latency() {
    for policy in ["min", "min_avg10", "min_moving_avg"] {
        let group_body = format!(
            r#"
            filter: name(node_a, node_b)
            policy: {policy}
            "#
        );
        let config = two_node_latency_config("", &group_body);
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();

        group
            .record_check_result("node_a", NetworkType::TCP4, Some(80), 1)
            .unwrap();
        group
            .record_check_result("node_b", NetworkType::TCP4, Some(40), 2)
            .unwrap();
        assert_eq!(
            group.select_proxy_for_tcp().unwrap().node_tag,
            "node_b",
            "policy {policy} should initially select the lower latency node"
        );

        group
            .record_manual_latency_result_for_link(
                &socks5_endpoint_fixture_url(FixtureEndpoint::Secondary),
                NetworkType::TCP4,
                None,
                3,
            )
            .unwrap();
        assert_eq!(
            group.select_proxy_for_tcp().unwrap().node_tag,
            "node_a",
            "policy {policy} should not select a failed manual latency result"
        );

        group
            .record_check_result("node_b", NetworkType::TCP4, Some(30), 4)
            .unwrap();
        assert_eq!(
            group.select_proxy_for_tcp().unwrap().node_tag,
            "node_b",
            "policy {policy} should recover without a failed placeholder in latency history"
        );
    }
}
