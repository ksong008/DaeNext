#[test]
    fn resident_dataplane_plan_selects_vless_group_node() {
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
    fn group_node_selection_keeps_fixed_policy_order() {
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
    fn group_node_selection_supports_generic_name_filters() {
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
    fn resident_dataplane_plan_keeps_non_fixed_group_candidates() {
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
    fn resident_dataplane_plan_wires_min_policy_latency_state() {
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

    #[test]
    fn resident_dataplane_group_tcp_check_uses_group_override() {
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
    fn resident_dataplane_group_tcp_check_accepts_https() {
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
    fn resident_manual_probe_plans_cover_all_admitted_config_nodes() {
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
    fn resident_dataplane_group_udp_check_uses_group_override_ipv4() {
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

    #[test]
    fn resident_dataplane_min_policy_selects_checked_lowest_last_latency() {
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
    fn resident_dataplane_min_avg10_policy_uses_latency_history() {
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
    fn resident_dataplane_min_moving_avg_policy_uses_moving_average() {
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
    fn resident_dataplane_min_policy_honors_group_check_tolerance() {
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
    fn resident_dataplane_min_policy_applies_add_latency_to_sorting_only() {
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

    #[test]
    fn resident_dataplane_plan_keeps_fixed_from_building_unselected_candidate() {
        let unsupported = vless_xhttp_parser_fixture_url("packet-up", "h3", "");
        let config_text = r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
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
        .replace("__UNSUPPORTED_SOURCE__", &unsupported);
        let config = parse_config(&config_text);
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        assert_eq!(group.candidate_count(), 2);
        assert_eq!(group.admitted_candidate_count(), 1);
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_a");
    }

    #[test]
    fn resident_dataplane_plan_does_not_fallback_unresolved_name_filter_to_static_ss_node() {
        let candidate = vless_xhttp_parser_fixture_url("packet-up", "h3", "");
        let config_text = r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        _022: 'ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==@217.116.171.227:25868'
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
        .replace("__CANDIDATE_SOURCE__", &candidate);
        let config = parse_config(&config_text);
        let err = build_resident_dataplane_plan(&config).unwrap_err();
        assert!(err.contains("cannot resolve group proxy name filter node(s): node_17"));
        assert!(!err.contains("parse VLESS node _022"));
    }
