use super::*;
use std::net::{IpAddr, SocketAddr};

#[test]
pub(super) fn resident_dataplane_group_tcp_check_uses_group_override() {
    let node_a = socks5_endpoint_fixture_url(FixtureEndpoint::Primary);
    let node_b = socks5_endpoint_fixture_url(FixtureEndpoint::Secondary);
    let global_check = tcp_check_fixture_url(
        HttpScheme::Http,
        FixtureEndpoint::Tertiary,
        "/generate_204",
        None,
    );
    let group_check = tcp_check_fixture_url(
        HttpScheme::Http,
        FixtureEndpoint::Authority,
        "/check?q=1",
        None,
    );
    let group_host = fixture_host(FixtureEndpoint::Authority);
    let config_text = r#"
        global {
        lan_interface: daerust0
        tcp_check_url: '__GLOBAL_CHECK__'
        tcp_check_http_method: GET
        }
        node {
        node_a: '__NODE_A__'
        node_b: '__NODE_B__'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: min
            tcp_check_url: '__GROUP_CHECK__'
            tcp_check_http_method: HEAD
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#
    .replace("__GLOBAL_CHECK__", &global_check)
    .replace("__GROUP_CHECK__", &group_check)
    .replace("__NODE_A__", &node_a)
    .replace("__NODE_B__", &node_b);
    let config = parse_config(&config_text);
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    let probes = group.probe_candidates();
    assert_eq!(probes[0].tcp_check.scheme, "http");
    assert_eq!(probes[0].tcp_check.target, format!("{group_host}:80"));
    assert_eq!(probes[0].tcp_check.host, group_host);
    assert_eq!(probes[0].tcp_check.path, "/check?q=1");
    assert_eq!(probes[0].tcp_check.method, "HEAD");
}

#[test]
pub(super) fn resident_dataplane_group_tcp_check_accepts_https() {
    let node_a = socks5_endpoint_fixture_url(FixtureEndpoint::Primary);
    let probe_target = Ipv4Addr::LOCALHOST.to_string();
    let check = tcp_check_fixture_url(
        HttpScheme::Https,
        FixtureEndpoint::Authority,
        "/generate_204",
        Some(&probe_target),
    );
    let check_host = fixture_host(FixtureEndpoint::Authority);
    let config_source = r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: '__NODE_A__'
        }
        group {
        proxy {
            filter: name(node_a)
            policy: min
            tcp_check_url: '__CHECK__'
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#
    .replace("__NODE_A__", &node_a)
    .replace("__CHECK__", &check);
    let config = parse_config(&config_source);
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let probes = plan.default_proxy_group().unwrap().probe_candidates();
    assert_eq!(probes[0].tcp_check.scheme, "https");
    assert_eq!(probes[0].tcp_check.target, format!("{probe_target}:443"));
    assert_eq!(probes[0].tcp_check.host, check_host);
    assert_eq!(probes[0].tcp_check.path, "/generate_204");
}

#[test]
pub(super) fn resident_manual_probe_plans_cover_all_admitted_config_nodes() {
    let grouped = socks5_endpoint_fixture_url(FixtureEndpoint::Primary);
    let orphan_source = socks5_endpoint_fixture_url(FixtureEndpoint::Secondary);
    let unsupported_source = unsupported_endpoint_fixture_url(FixtureEndpoint::Tertiary);
    let probe_target = Ipv4Addr::LOCALHOST.to_string();
    let check = tcp_check_fixture_url(
        HttpScheme::Http,
        FixtureEndpoint::Authority,
        "/generate_204",
        Some(&probe_target),
    );
    let check_host = fixture_host(FixtureEndpoint::Authority);
    let config_source = r#"
        global {
        lan_interface: daerust0
        tcp_check_url: '__CHECK__'
        tcp_check_http_method: GET
        }
        node {
        grouped: '__GROUPED__'
        orphan: '__ORPHAN__'
        unsupported: '__UNSUPPORTED__'
        }
        group {
        proxy {
            filter: name(grouped)
            policy: fixed
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#
    .replace("__CHECK__", &check)
    .replace("__GROUPED__", &grouped)
    .replace("__ORPHAN__", &orphan_source)
    .replace("__UNSUPPORTED__", &unsupported_source);
    let config = parse_config(&config_source);
    let plans = build_resident_manual_probe_plans(&config);
    let orphan = plans
        .get(&orphan_source)
        .expect("orphan node should be indexed")
        .as_ref()
        .expect("orphan socks node should be admitted");
    assert_eq!(orphan.node_tag, "orphan");
    assert_eq!(orphan.tcp_check.method, "GET");
    assert_eq!(orphan.tcp_check.target, format!("{probe_target}:80"));
    assert_eq!(orphan.tcp_check.host, check_host);
    assert!(
        plans
            .get(&unsupported_source)
            .expect("unsupported node should be indexed")
            .is_err()
    );
}

#[test]
pub(super) fn resident_latency_probe_plans_do_not_keep_xhttp_xmux_clients() {
    let xhttp = vless_xhttp_parser_fixture_url(
        "packet-up",
        "h2",
        r#"{"xmux":{"maxConnections":2},"downloadSettings":{"address":"download.transport.invalid","port":18444,"network":"xhttp","security":"tls","tlsSettings":{"serverName":"download.sni.invalid","alpn":["h2"]},"xhttpSettings":{"host":"download.host.invalid","path":"/down?ed=4096","mode":"stream-up","extra":{"xmux":{"maxConnections":3}}}}}"#,
    );
    let config_source = r#"
        global {
        lan_interface: daerust0
        }
        node {
        xhttp: '__XHTTP__'
        }
        group {
        proxy {
            filter: name(xhttp)
            policy: min
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#
    .replace("__XHTTP__", &xhttp);
    let config = parse_config(&config_source);

    let runtime_plan = build_resident_dataplane_plan(&config).unwrap();
    let runtime_proxy = runtime_plan
        .default_proxy_group()
        .unwrap()
        .default_proxy_snapshot()
        .unwrap();
    assert!(runtime_proxy.xhttp_xmux.is_some());
    assert!(
        runtime_proxy
            .xhttp_download
            .as_ref()
            .unwrap()
            .xmux
            .is_some()
    );

    let group_probe = runtime_plan
        .default_proxy_group()
        .unwrap()
        .probe_candidates()
        .into_iter()
        .next()
        .unwrap();
    assert!(group_probe.proxy.xhttp_xmux.is_none());
    assert!(
        group_probe
            .proxy
            .xhttp_download
            .as_ref()
            .unwrap()
            .xmux
            .is_none()
    );

    let manual_plans = build_resident_manual_probe_plans(&config);
    let manual_probe = manual_plans
        .get(&xhttp)
        .expect("xHTTP node should be indexed")
        .as_ref()
        .expect("xHTTP node should be admitted");
    assert!(manual_probe.proxy.xhttp_xmux.is_none());
    assert!(
        manual_probe
            .proxy
            .xhttp_download
            .as_ref()
            .unwrap()
            .xmux
            .is_none()
    );
}

#[test]
pub(super) fn resident_dataplane_group_udp_check_uses_group_override_ipv4() {
    let node_a = socks5_endpoint_fixture_url(FixtureEndpoint::Primary);
    let global_dns_host = fixture_host(FixtureEndpoint::Tertiary);
    let group_dns_host = fixture_host(FixtureEndpoint::Authority);
    let global_dns_target = Ipv4Addr::LOCALHOST;
    let group_dns_target = Ipv4Addr::LOCALHOST;
    let global_dns = format!(
        "{}:{},{}",
        global_dns_host,
        fixture_endpoint_port(FixtureEndpoint::Tertiary),
        global_dns_target
    );
    let group_dns_port = fixture_endpoint_port(FixtureEndpoint::Authority);
    let group_dns = format!("{}:{},{}", group_dns_host, group_dns_port, group_dns_target);
    let config_text = r#"
        global {
        lan_interface: daerust0
        udp_check_dns: '__GLOBAL_DNS__'
        }
        node {
        node_a: '__NODE_A__'
        }
        group {
        proxy {
            filter: name(node_a)
            policy: min
            udp_check_dns: '__GROUP_DNS__'
        }
        }
        routing {
        l4proto(udp) -> proxy
        fallback: direct
        }
        "#
    .replace("__GLOBAL_DNS__", &global_dns)
    .replace("__GROUP_DNS__", &group_dns)
    .replace("__NODE_A__", &node_a);
    let config = parse_config(&config_text);
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let probes = plan.default_proxy_group().unwrap().probe_candidates();
    assert_eq!(
        probes[0].udp_check.target.literal_addr(),
        Some(SocketAddr::V4(SocketAddrV4::new(
            group_dns_target,
            group_dns_port
        )))
    );
    assert_eq!(
        probes[0].udp_check.target.authority(),
        SocketAddrV4::new(group_dns_target, group_dns_port).to_string()
    );
    assert_eq!(probes[0].udp_check.host, group_dns_host);
    assert_eq!(
        probes[0].udp_check.lookup_host,
        "connectivitycheck.gstatic.com."
    );
}

#[test]
pub(super) fn resident_dataplane_group_udp_check_accepts_single_ip_default_port() {
    let node_a = socks5_endpoint_fixture_url(FixtureEndpoint::Primary);
    let check_ip = Ipv4Addr::LOCALHOST;
    let config_text = r#"
        global {
        lan_interface: daerust0
        udp_check_dns: '__CHECK_IP__'
        }
        node {
        node_a: '__NODE_A__'
        }
        group {
        proxy {
            filter: name(node_a)
            policy: min
        }
        }
        routing {
        l4proto(udp) -> proxy
        fallback: direct
        }
        "#
    .replace("__CHECK_IP__", &check_ip.to_string())
    .replace("__NODE_A__", &node_a);
    let config = parse_config(&config_text);
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let probes = plan.default_proxy_group().unwrap().probe_candidates();
    assert_eq!(
        probes[0].udp_check.target.literal_addr(),
        Some(SocketAddr::V4(SocketAddrV4::new(check_ip, 53)))
    );
}

#[test]
pub(super) fn resident_dataplane_group_udp_check_accepts_single_ipv6_default_port() {
    let node_a = socks5_endpoint_fixture_url(FixtureEndpoint::Primary);
    let check_ip = Ipv6Addr::LOCALHOST;
    let config_text = r#"
        global {
        lan_interface: daerust0
        udp_check_dns: '__CHECK_IP__'
        }
        node {
        node_a: '__NODE_A__'
        }
        group {
        proxy {
            filter: name(node_a)
            policy: min
        }
        }
        routing {
        l4proto(udp) -> proxy
        fallback: direct
        }
        "#
    .replace("__CHECK_IP__", &check_ip.to_string())
    .replace("__NODE_A__", &node_a);
    let config = parse_config(&config_text);
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let probes = plan.default_proxy_group().unwrap().probe_candidates();
    assert_eq!(
        probes[0].udp_check.target.literal_addr(),
        Some(SocketAddr::new(IpAddr::V6(check_ip), 53))
    );
}

#[test]
pub(super) fn resident_dataplane_group_udp_check_accepts_single_domain_default_port() {
    let node_a = socks5_endpoint_fixture_url(FixtureEndpoint::Primary);
    let check_host = fixture_host(FixtureEndpoint::Authority);
    let config_text = r#"
        global {
        lan_interface: daerust0
        udp_check_dns: '__CHECK_HOST__'
        }
        node {
        node_a: '__NODE_A__'
        }
        group {
        proxy {
            filter: name(node_a)
            policy: min
        }
        }
        routing {
        l4proto(udp) -> proxy
        fallback: direct
        }
        "#
    .replace("__CHECK_HOST__", &check_host)
    .replace("__NODE_A__", &node_a);
    let config = parse_config(&config_text);
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let probes = plan.default_proxy_group().unwrap().probe_candidates();
    assert_eq!(probes[0].udp_check.host, check_host);
    assert_eq!(
        probes[0].udp_check.target.authority(),
        format!("{check_host}:53")
    );
    assert_eq!(probes[0].udp_check.target.literal_addr(), None);
}
