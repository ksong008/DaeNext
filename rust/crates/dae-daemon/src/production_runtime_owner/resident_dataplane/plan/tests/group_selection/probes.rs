use super::*;
#[test]
pub(super) fn resident_dataplane_group_tcp_check_uses_group_override() {
    let config = parse_config(
        r#"
        global {
        lan_interface: daerust0
        tcp_check_url: 'http://global.example/generate_204'
        tcp_check_http_method: GET
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: min
            tcp_check_url: 'http://group.example/check?q=1'
            tcp_check_http_method: HEAD
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
    let probes = group.probe_candidates();
    assert_eq!(probes[0].tcp_check.scheme, "http");
    assert_eq!(probes[0].tcp_check.target, "group.example:80");
    assert_eq!(probes[0].tcp_check.host, "group.example");
    assert_eq!(probes[0].tcp_check.path, "/check?q=1");
    assert_eq!(probes[0].tcp_check.method, "HEAD");
}

#[test]
pub(super) fn resident_dataplane_group_tcp_check_accepts_https() {
    let config = parse_config(
        r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        }
        group {
        proxy {
            filter: name(node_a)
            policy: min
            tcp_check_url: 'https://check.example/generate_204,203.0.113.7'
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let probes = plan.default_proxy_group().unwrap().probe_candidates();
    assert_eq!(probes[0].tcp_check.scheme, "https");
    assert_eq!(probes[0].tcp_check.target, "203.0.113.7:443");
    assert_eq!(probes[0].tcp_check.host, "check.example");
    assert_eq!(probes[0].tcp_check.path, "/generate_204");
}

#[test]
pub(super) fn resident_manual_probe_plans_cover_all_admitted_config_nodes() {
    let config = parse_config(
        r#"
        global {
        lan_interface: daerust0
        tcp_check_url: 'http://check.example/generate_204,203.0.113.7'
        tcp_check_http_method: GET
        }
        node {
        grouped: 'socks://127.0.0.1:1080'
        orphan: 'socks://127.0.0.1:1081'
        unsupported: 'wireguard://198.51.100.2:51820'
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
        "#,
    );
    let plans = build_resident_manual_probe_plans(&config);
    let orphan = plans
        .get("socks://127.0.0.1:1081")
        .expect("orphan node should be indexed")
        .as_ref()
        .expect("orphan socks node should be admitted");
    assert_eq!(orphan.node_tag, "orphan");
    assert_eq!(orphan.tcp_check.method, "GET");
    assert_eq!(orphan.tcp_check.target, "203.0.113.7:80");
    assert_eq!(orphan.tcp_check.host, "check.example");
    assert!(
        plans
            .get("wireguard://198.51.100.2:51820")
            .expect("unsupported node should be indexed")
            .is_err()
    );
}

#[test]
pub(super) fn resident_dataplane_group_udp_check_uses_group_override_ipv4() {
    let config = parse_config(
        r#"
        global {
        lan_interface: daerust0
        udp_check_dns: 'dns.global:53,8.8.8.8'
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        }
        group {
        proxy {
            filter: name(node_a)
            policy: min
            udp_check_dns: 'dns.group:5353,8.8.4.4'
        }
        }
        routing {
        l4proto(udp) -> proxy
        fallback: direct
        }
        "#,
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let probes = plan.default_proxy_group().unwrap().probe_candidates();
    assert_eq!(
        probes[0].udp_check.target,
        SocketAddrV4::new(Ipv4Addr::new(8, 8, 4, 4), 5353)
    );
    assert_eq!(probes[0].udp_check.host, "dns.group");
    assert_eq!(
        probes[0].udp_check.lookup_host,
        "connectivitycheck.gstatic.com."
    );
}
