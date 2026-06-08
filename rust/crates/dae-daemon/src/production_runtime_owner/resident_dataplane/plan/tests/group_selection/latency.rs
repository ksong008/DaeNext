use super::*;
#[test]
pub(super) fn resident_dataplane_min_policy_selects_checked_lowest_last_latency() {
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
            policy: min
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
            policy: min_avg10
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
    let config = parse_config(
        r#"
        global {
        lan_interface: daerust0
        check_tolerance: 10ms
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: min
            check_tolerance: 50ms
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
            filter: name(node_a) [add_latency: 100ms]
            filter: name(node_b)
            policy: min
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
    assert_eq!(group.annotation_latency_offset_count(), 1);
    group
        .record_check_result("node_a", NetworkType::TCP4, Some(50), 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::TCP4, Some(90), 2)
        .unwrap();
    assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
}
