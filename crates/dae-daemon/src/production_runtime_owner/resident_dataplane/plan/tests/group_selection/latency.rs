use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

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

fn latency_dual_stack_probe_targets() -> String {
    format!("{},{}", Ipv6Addr::LOCALHOST, Ipv4Addr::LOCALHOST)
}

fn latency_ipv6_probe_target() -> String {
    Ipv6Addr::LOCALHOST.to_string()
}

fn latency_tcp_check_url(targets: &str) -> String {
    tcp_check_fixture_url(
        HttpScheme::Http,
        FixtureEndpoint::Authority,
        "/",
        Some(targets),
    )
}

fn latency_udp_check_dns(targets: &str) -> String {
    format!(
        "{}:{},{}",
        fixture_host(FixtureEndpoint::Authority),
        fixture_endpoint_port(FixtureEndpoint::Authority),
        targets
    )
}

fn latency_tcp_dual_stack_check_url() -> String {
    latency_tcp_check_url(&latency_dual_stack_probe_targets())
}

fn latency_udp_dual_stack_check_dns() -> String {
    latency_udp_check_dns(&latency_dual_stack_probe_targets())
}

fn latency_tcp_ipv6_check_url() -> String {
    latency_tcp_check_url(&latency_ipv6_probe_target())
}

fn latency_udp_ipv6_check_dns() -> String {
    latency_udp_check_dns(&latency_ipv6_probe_target())
}

fn assert_runtime_tcp_min_uses_requested_family_when_alive(policy: &str) {
    let tcp_check = latency_tcp_dual_stack_check_url();
    let group_body = format!(
        r#"
        filter: name(node_a, node_b)
        policy: {policy}
        tcp_check_url: '{tcp_check}'
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
    let udp_check = latency_udp_dual_stack_check_dns();
    let group_body = format!(
        r#"
        filter: name(node_a, node_b)
        policy: {policy}
        udp_check_dns: '{udp_check}'
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
    let tcp_check = latency_tcp_dual_stack_check_url();
    let config = two_node_latency_config(
        "",
        &format!(
            r#"
        filter: name(node_a, node_b)
        policy: min
        tcp_check_url: '{tcp_check}'
        "#
        ),
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
    let udp_check = latency_udp_dual_stack_check_dns();
    let config = two_node_latency_config(
        "",
        &format!(
            r#"
        filter: name(node_a, node_b)
        policy: min
        udp_check_dns: '{udp_check}'
        "#
        ),
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
pub(super) fn resident_dataplane_dns_upstream_selection_can_fallback_family() {
    let udp_check = latency_udp_dual_stack_check_dns();
    let config = two_node_latency_config(
        "",
        &format!(
            r#"
        filter: name(node_a, node_b)
        policy: min
        udp_check_dns: '{udp_check}'
        "#
        ),
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

    assert_eq!(
        group
            .select_proxy_for_dns_upstream(NetworkType::DNS_UDP4)
            .unwrap()
            .node_tag,
        "node_b"
    );
    assert!(
        group
            .select_proxy_for_udp_runtime(NetworkType::DNS_UDP4, true)
            .is_err()
    );

    let tcp_check = latency_tcp_dual_stack_check_url();
    let config = two_node_latency_config(
        "",
        &format!(
            r#"
        filter: name(node_a, node_b)
        policy: min
        tcp_check_url: '{tcp_check}'
        "#
        ),
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
            .select_proxy_for_dns_upstream(NetworkType::TCP4)
            .unwrap()
            .node_tag,
        "node_b"
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
    assert!(group.select_proxy_for_tcp().is_err());

    let node_b_hash = group
        .probe_candidates()
        .into_iter()
        .find(|candidate| candidate.node_tag == "node_b")
        .unwrap()
        .link_hash;
    group
        .apply_health_seed_snapshot(&serde_json::json!({
            "linkHash": node_b_hash,
            "latencyMs": 25,
            "alive": true,
            "checkedAtUnix": 42,
            "scope": "proxy-tcp-check",
        }))
        .unwrap();

    assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
    assert!(group.select_proxy_for_udp().is_err());
}

#[test]
pub(super) fn resident_dataplane_database_health_seed_is_bounded_by_check_interval() {
    let config = two_node_latency_config(
        "check_interval: 30s",
        r#"
        filter: name(node_a, node_b)
        policy: min
        "#,
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let fresh_plan = build_resident_dataplane_plan(&config).unwrap();
    let fresh_group = fresh_plan.default_proxy_group().unwrap();
    let candidate = fresh_group
        .probe_candidates()
        .into_iter()
        .find(|candidate| candidate.node_tag == "node_b")
        .unwrap();
    assert_eq!(
        fresh_group
            .apply_health_seed_snapshot(&serde_json::json!({
                "executionIdentity": candidate.execution_identity,
                "networkDimension": NetworkType::TCP4.dimension_name(),
                "latencyMs": 25,
                "alive": true,
                "checkedAtUnix": now,
                "seedSource": "database",
            }))
            .unwrap(),
        1
    );

    let expired_plan = build_resident_dataplane_plan(&config).unwrap();
    let expired_group = expired_plan.default_proxy_group().unwrap();
    assert_eq!(
        expired_group
            .apply_health_seed_snapshot(&serde_json::json!({
                "executionIdentity": candidate.execution_identity,
                "networkDimension": NetworkType::TCP4.dimension_name(),
                "latencyMs": 25,
                "alive": true,
                "checkedAtUnix": now - 61,
                "seedSource": "database",
            }))
            .unwrap(),
        0
    );
    assert!(expired_group.select_proxy_for_tcp().is_err());
}

#[test]
pub(super) fn resident_dataplane_latency_snapshots_follow_configured_tcp_ip_family() {
    let tcp_check = latency_tcp_ipv6_check_url();
    let config = two_node_latency_config(
        "",
        &format!(
            r#"
        filter: name(node_a, node_b)
        policy: min
        tcp_check_url: '{tcp_check}'
        "#
        ),
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
    let tcp_check = latency_tcp_ipv6_check_url();
    let udp_check = latency_udp_ipv6_check_dns();
    let config = two_node_latency_config(
        "",
        &format!(
            r#"
        filter: name(node_a, node_b)
        policy: min
        tcp_check_url: '{tcp_check}'
        udp_check_dns: '{udp_check}'
        "#
        ),
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    assert!(
        group
            .select_proxy_for_tcp_network(NetworkType::TCP6)
            .is_err()
    );

    let node_b_hash = group
        .probe_candidates()
        .into_iter()
        .find(|candidate| candidate.node_tag == "node_b")
        .unwrap()
        .link_hash;
    let applied = group
        .apply_health_seed_snapshot(&serde_json::json!({
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
    assert!(
        group
            .select_proxy_for_udp_network(NetworkType::DNS_UDP6)
            .is_err()
    );
}

#[test]
pub(super) fn resident_dataplane_legacy_latency_seed_does_not_invent_ipv6_state() {
    let tcp_check = latency_tcp_ipv6_check_url();
    let udp_check = latency_udp_ipv6_check_dns();
    let config = two_node_latency_config(
        "",
        &format!(
            r#"
        filter: name(node_a, node_b)
        policy: min
        tcp_check_url: '{tcp_check}'
        udp_check_dns: '{udp_check}'
        "#
        ),
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
        .apply_health_seed_snapshot(&serde_json::json!({
            "linkHash": node_b_hash,
            "latencyMs": 25,
            "alive": true,
            "checkedAtUnix": 42,
        }))
        .unwrap();

    assert_eq!(applied, 0);
    assert!(
        group
            .select_proxy_for_tcp_network(NetworkType::TCP6)
            .is_err()
    );
}

#[test]
pub(super) fn resident_dataplane_health_seed_restores_dead_and_unavailable_exact_dimensions() {
    let config = two_node_latency_config(
        "",
        r#"
        filter: name(node_a, node_b)
        policy: min
        "#,
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    let candidate = group
        .probe_candidates()
        .into_iter()
        .find(|candidate| candidate.node_tag == "node_b")
        .unwrap();

    for (network_type, health_state, checked_at) in [
        (NetworkType::TCP4, HealthState::Dead, 41),
        (NetworkType::TCP6, HealthState::Unavailable, 42),
    ] {
        let applied = group
            .apply_health_seed_snapshot(&serde_json::json!({
                "executionIdentity": candidate.execution_identity,
                "linkHash": candidate.link_hash,
                "networkDimension": network_type.dimension_name(),
                "healthState": health_state.as_str(),
                "alive": false,
                "latencyMs": null,
                "checkedAtUnix": checked_at,
                "lastFailureAtUnix": if health_state == HealthState::Dead { checked_at } else { 0 },
                "targetIdentity": group.health_target_identity(network_type),
            }))
            .unwrap();
        assert_eq!(applied, 1);
    }

    let snapshots = group.health_state_snapshots();
    let tcp4 = snapshots
        .iter()
        .find(|snapshot| {
            snapshot.node_tag == "node_b" && snapshot.network_type == NetworkType::TCP4
        })
        .unwrap();
    let tcp6 = snapshots
        .iter()
        .find(|snapshot| {
            snapshot.node_tag == "node_b" && snapshot.network_type == NetworkType::TCP6
        })
        .unwrap();
    assert_eq!(tcp4.health_state, HealthState::Dead);
    assert_eq!(tcp4.latency_ms, None);
    assert_eq!(tcp4.last_failure_at_unix, 41);
    assert_eq!(tcp6.health_state, HealthState::Unavailable);
    assert_eq!(tcp6.latency_ms, None);
    assert_ne!(tcp4.latency_ms, Some(dae_outbound::dialer::TIMEOUT_MS));
    assert_ne!(tcp6.latency_ms, Some(dae_outbound::dialer::TIMEOUT_MS));
}

#[test]
pub(super) fn resident_dataplane_health_unknown_preserves_last_known_state_and_freshness() {
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
        .record_health_state(
            "node_b",
            NetworkType::TCP4,
            HealthState::Alive,
            Some(27),
            10,
        )
        .unwrap();
    group
        .record_health_state("node_b", NetworkType::TCP4, HealthState::Unknown, None, 11)
        .unwrap();

    let snapshot = group
        .health_state_snapshots()
        .into_iter()
        .find(|snapshot| {
            snapshot.node_tag == "node_b" && snapshot.network_type == NetworkType::TCP4
        })
        .unwrap();
    assert_eq!(snapshot.health_state, HealthState::Alive);
    assert_eq!(snapshot.latency_ms, Some(27));
    assert_eq!(snapshot.last_success_at_unix, 10);
    assert_eq!(snapshot.last_unknown_at_unix, 11);
}

#[test]
pub(super) fn resident_dataplane_health_seed_uses_execution_and_target_identity() {
    let config = two_node_latency_config(
        "",
        r#"
        filter: name(node_a, node_b)
        policy: min
        "#,
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    let candidate = group
        .probe_candidates()
        .into_iter()
        .find(|candidate| candidate.node_tag == "node_b")
        .unwrap();
    let snapshot = serde_json::json!({
        "executionIdentity": candidate.execution_identity,
        "linkHash": link_hash("display-name-only-change"),
        "networkDimension": NetworkType::TCP4.dimension_name(),
        "healthState": HealthState::Alive.as_str(),
        "alive": true,
        "latencyMs": 31,
        "checkedAtUnix": 15,
        "targetIdentity": group.health_target_identity(NetworkType::TCP4),
    });
    assert_eq!(group.apply_health_seed_snapshot(&snapshot).unwrap(), 1);

    let mut changed_execution = snapshot.clone();
    changed_execution["executionIdentity"] = serde_json::json!(execution_link_hash(
        &socks5_endpoint_fixture_url(FixtureEndpoint::Tertiary)
    ));
    assert_eq!(
        group
            .apply_health_seed_snapshot(&changed_execution)
            .unwrap(),
        0
    );

    let mut changed_target = snapshot;
    changed_target["targetIdentity"] = serde_json::json!(link_hash("changed-health-target"));
    assert_eq!(
        group.apply_health_seed_snapshot(&changed_target).unwrap(),
        0
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
        .apply_health_seed_snapshot(&serde_json::json!({
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

#[test]
pub(super) fn resident_dataplane_resuscitation_is_rate_limited_and_skips_fixed() {
    let config = two_node_latency_config(
        "",
        r#"
        filter: name(node_a, node_b)
        policy: min
        "#,
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();

    assert!(group.try_begin_resuscitation(NetworkType::DATA_UDP4));
    assert!(!group.try_begin_resuscitation(NetworkType::DATA_UDP4));
    assert!(group.try_begin_resuscitation(NetworkType::TCP4));

    let fixed_config = two_node_latency_config(
        "",
        r#"
        filter: name(node_a, node_b)
        policy: fixed(0)
        "#,
    );
    let fixed_plan = build_resident_dataplane_plan(&fixed_config).unwrap();
    let fixed_group = fixed_plan.default_proxy_group().unwrap();

    assert!(!fixed_group.try_begin_resuscitation(NetworkType::DATA_UDP4));
}
