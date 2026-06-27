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

fn assert_runtime_tcp_min_uses_requested_family_when_alive(policy: &str) {
    let group_body = format!(
        r#"
        filter: name(node_a, node_b)
        policy: {policy}
        tcp_check_url: 'http://cp.cloudflare.com,::1,127.0.0.1'
        "#
    );
    let config = two_node_latency_config("", &group_body);
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    group
        .record_check_result("node_a", NetworkType::TCP4, Some(20), 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::TCP6, Some(50), 2)
        .unwrap();
    assert_eq!(
        group
            .select_proxy_for_tcp_runtime(NetworkType::TCP4, false)
            .unwrap()
            .node_tag,
        "node_a"
    );

    let config = two_node_latency_config("", &group_body);
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    group
        .record_check_result("node_a", NetworkType::TCP4, Some(300), 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::TCP6, Some(50), 2)
        .unwrap();
    assert_eq!(
        group
            .select_proxy_for_tcp_runtime(NetworkType::TCP4, false)
            .unwrap()
            .node_tag,
        "node_a"
    );
}

fn assert_runtime_udp_min_uses_requested_family_when_alive(policy: &str) {
    let group_body = format!(
        r#"
        filter: name(node_a, node_b)
        policy: {policy}
        udp_check_dns: 'dns.google:53,::1,127.0.0.1'
        "#
    );
    let config = two_node_latency_config("", &group_body);
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    group
        .record_check_result("node_a", NetworkType::DNS_UDP4, Some(20), 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::DNS_UDP6, Some(50), 2)
        .unwrap();
    assert_eq!(
        group
            .select_proxy_for_udp_runtime(NetworkType::DNS_UDP4, true)
            .unwrap()
            .node_tag,
        "node_a"
    );

    let config = two_node_latency_config("", &group_body);
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    group
        .record_check_result("node_a", NetworkType::DNS_UDP4, Some(300), 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::DNS_UDP6, Some(50), 2)
        .unwrap();
    assert_eq!(
        group
            .select_proxy_for_udp_runtime(NetworkType::DNS_UDP4, true)
            .unwrap()
            .node_tag,
        "node_a"
    );
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
pub(super) fn resident_dataplane_tcp_selection_uses_requested_ip_family_latency() {
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
        .record_check_result("node_a", NetworkType::TCP4, Some(20), 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::TCP4, Some(200), 2)
        .unwrap();
    group
        .record_check_result("node_a", NetworkType::TCP6, Some(300), 3)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::TCP6, Some(50), 4)
        .unwrap();

    assert_eq!(
        group
            .select_proxy_for_tcp_network(NetworkType::TCP4)
            .unwrap()
            .node_tag,
        "node_a"
    );
    assert_eq!(
        group
            .select_proxy_for_tcp_network(NetworkType::TCP6)
            .unwrap()
            .node_tag,
        "node_b"
    );
}

#[test]
pub(super) fn resident_dataplane_runtime_tcp_min_uses_requested_family_when_alive() {
    for policy in ["min", "min_avg10", "min_moving_avg"] {
        assert_runtime_tcp_min_uses_requested_family_when_alive(policy);
    }
}

#[test]
pub(super) fn resident_dataplane_runtime_tcp_domain_falls_back_when_requested_family_has_no_alive()
{
    let config = two_node_latency_config(
        "",
        r#"
        filter: name(node_a, node_b)
        policy: min
        tcp_check_url: 'http://cp.cloudflare.com,::1,127.0.0.1'
        "#,
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    group
        .record_check_result("node_a", NetworkType::TCP4, None, 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::TCP4, None, 2)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::TCP6, Some(50), 3)
        .unwrap();

    assert_eq!(
        group
            .select_proxy_for_tcp_runtime(NetworkType::TCP4, false)
            .unwrap()
            .node_tag,
        "node_b"
    );
    assert!(
        group
            .select_proxy_for_tcp_runtime(NetworkType::TCP4, true)
            .is_err()
    );
}

#[test]
pub(super) fn resident_dataplane_runtime_udp_min_uses_requested_family_when_alive() {
    for policy in ["min", "min_avg10", "min_moving_avg"] {
        assert_runtime_udp_min_uses_requested_family_when_alive(policy);
    }
}

#[test]
pub(super) fn resident_dataplane_runtime_udp_strict_family_does_not_fallback() {
    let config = two_node_latency_config(
        "",
        r#"
        filter: name(node_a, node_b)
        policy: min
        udp_check_dns: 'dns.google:53,::1,127.0.0.1'
        "#,
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    group
        .record_check_result("node_a", NetworkType::DNS_UDP4, None, 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::DNS_UDP4, None, 2)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::DNS_UDP6, Some(50), 3)
        .unwrap();

    assert!(
        group
            .select_proxy_for_udp_runtime(NetworkType::DNS_UDP4, true)
            .is_err()
    );
}

#[test]
pub(super) fn resident_dataplane_udp_selection_uses_requested_ip_family_latency() {
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
        .record_check_result("node_a", NetworkType::DNS_UDP4, Some(20), 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::DNS_UDP4, Some(200), 2)
        .unwrap();
    group
        .record_check_result("node_a", NetworkType::DNS_UDP6, Some(300), 3)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::DNS_UDP6, Some(50), 4)
        .unwrap();

    assert_eq!(
        group
            .select_proxy_for_udp_network(NetworkType::DNS_UDP4)
            .unwrap()
            .node_tag,
        "node_a"
    );
    assert_eq!(
        group
            .select_proxy_for_udp_network(NetworkType::DNS_UDP6)
            .unwrap()
            .node_tag,
        "node_b"
    );
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

#[test]
pub(super) fn resident_dataplane_latency_seed_selects_dynamic_group_candidate() {
    let config = two_node_latency_config(
        "",
        r#"
        filter: name(node_a, node_b)
        policy: min
        "#,
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_a");

    let node_b_hash = group
        .probe_candidates()
        .into_iter()
        .find(|candidate| candidate.node_tag == "node_b")
        .unwrap()
        .link_hash;
    group
        .apply_successful_latency_seed_snapshot(&serde_json::json!({
            "linkHash": node_b_hash,
            "latencyMs": 25,
            "alive": true,
            "checkedAtUnix": 42,
        }))
        .unwrap();

    assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
    assert_eq!(group.select_proxy_for_udp().unwrap().node_tag, "node_b");
}

#[test]
pub(super) fn resident_dataplane_latency_snapshots_follow_configured_tcp_ip_family() {
    let config = two_node_latency_config(
        "",
        r#"
        filter: name(node_a, node_b)
        policy: min
        tcp_check_url: 'http://cp.cloudflare.com,::1'
        "#,
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    group
        .record_check_result("node_a", NetworkType::TCP6, Some(33), 7)
        .unwrap();

    let snapshot = group
        .latency_snapshots()
        .into_iter()
        .find(|snapshot| snapshot.node_tag == "node_a")
        .unwrap();
    assert_eq!(snapshot.network_type, NetworkType::TCP6);
    assert_eq!(snapshot.latency_ms, Some(33));
    assert!(snapshot.alive);
    assert_eq!(snapshot.checked_at_unix, 7);
}

#[test]
pub(super) fn resident_dataplane_latency_seed_uses_snapshot_ip_family_when_present() {
    let config = two_node_latency_config(
        "",
        r#"
        filter: name(node_a, node_b)
        policy: min
        tcp_check_url: 'http://cp.cloudflare.com,::1'
        udp_check_dns: 'dns.google:53,::1'
        "#,
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    assert_eq!(
        group
            .select_proxy_for_tcp_network(NetworkType::TCP6)
            .unwrap()
            .node_tag,
        "node_a"
    );

    let node_b_hash = group
        .probe_candidates()
        .into_iter()
        .find(|candidate| candidate.node_tag == "node_b")
        .unwrap()
        .link_hash;
    let applied = group
        .apply_successful_latency_seed_snapshot(&serde_json::json!({
            "linkHash": node_b_hash,
            "latencyMs": 25,
            "alive": true,
            "checkedAtUnix": 42,
            "networkType": NetworkType::TCP6.string_without_dns(),
        }))
        .unwrap();

    assert_eq!(applied, 1);
    assert_eq!(
        group
            .select_proxy_for_tcp_network(NetworkType::TCP6)
            .unwrap()
            .node_tag,
        "node_b"
    );
    assert_eq!(
        group
            .select_proxy_for_udp_network(NetworkType::DNS_UDP6)
            .unwrap()
            .node_tag,
        "node_b"
    );
}

#[test]
pub(super) fn resident_dataplane_legacy_latency_seed_does_not_invent_ipv6_state() {
    let config = two_node_latency_config(
        "",
        r#"
        filter: name(node_a, node_b)
        policy: min
        tcp_check_url: 'http://cp.cloudflare.com,::1'
        udp_check_dns: 'dns.google:53,::1'
        "#,
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    let node_b_hash = group
        .probe_candidates()
        .into_iter()
        .find(|candidate| candidate.node_tag == "node_b")
        .unwrap()
        .link_hash;
    let applied = group
        .apply_successful_latency_seed_snapshot(&serde_json::json!({
            "linkHash": node_b_hash,
            "latencyMs": 25,
            "alive": true,
            "checkedAtUnix": 42,
        }))
        .unwrap();

    assert_eq!(applied, 0);
    assert_eq!(
        group
            .select_proxy_for_tcp_network(NetworkType::TCP6)
            .unwrap()
            .node_tag,
        "node_a"
    );
}

#[test]
pub(super) fn resident_dataplane_latency_seed_does_not_change_fixed_group_selection() {
    let config = two_node_latency_config(
        "",
        r#"
        filter: name(node_a, node_b)
        policy: fixed(1)
        "#,
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");

    let node_b_hash = group
        .probe_candidates()
        .into_iter()
        .find(|candidate| candidate.node_tag == "node_b")
        .unwrap()
        .link_hash;
    let applied = group
        .apply_successful_latency_seed_snapshot(&serde_json::json!({
            "linkHash": node_b_hash,
            "latencyMs": 1,
            "alive": true,
            "checkedAtUnix": 42,
        }))
        .unwrap();

    assert_eq!(applied, 0);
    assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
    assert_eq!(group.select_proxy_for_udp().unwrap().node_tag, "node_b");
}
