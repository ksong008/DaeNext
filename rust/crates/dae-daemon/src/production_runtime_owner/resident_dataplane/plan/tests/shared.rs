use super::*;
    use dae_outbound::shadowsocks::Sip003;

    fn assert_protocol_matrix_source_uses_generic_semantics(source: &str) {
        let lower = source.to_ascii_lowercase();
        let forbidden_terms = [
            ["matrix", "-"].concat(),
            ["invalid", "-", "test", "-", "format"].concat(),
        ];
        for forbidden in forbidden_terms {
            assert!(
                !lower.contains(&forbidden),
                "protocol matrix source fixtures must use protocol-generic semantics, found {forbidden}"
            );
        }
        for link in url_like_source_literals(source) {
            assert_resident_source_fixture_uses_generic_semantics(&link);
        }
    }

    #[test]
    fn protocol_matrix_source_fixtures_use_generic_semantics() {
        for source in [
            include_str!("../../plan.rs"),
            include_str!("../model.rs"),
            include_str!("../transport_defaults.rs"),
            include_str!("../group_plan.rs"),
            include_str!("../dataplane_builder.rs"),
            include_str!("../group_selector.rs"),
            include_str!("../check_plans.rs"),
            include_str!("../proxy_builders.rs"),
            include_str!("../public_helpers.rs"),
            include_str!("../fingerprint_dial.rs"),
            include_str!("../selection_policy.rs"),
            include_str!("../link_parsing.rs"),
            include_str!("../tests.rs"),
            include_str!("shared.rs"),
            include_str!("group_selection.rs"),
            include_str!("resident_handlers.rs"),
            include_str!("matrix_blocked.rs"),
            include_str!("fingerprint.rs"),
        ] {
            assert_protocol_matrix_source_uses_generic_semantics(source);
        }
    }

    fn url_like_source_literals(source: &str) -> Vec<String> {
        let mut links = Vec::new();
        let mut offset = 0;
        while let Some(relative_pos) = source[offset..].find("://") {
            let scheme_end = offset + relative_pos;
            let mut start = scheme_end;
            while start > 0 {
                let previous = source.as_bytes()[start - 1];
                if previous.is_ascii_alphanumeric() || matches!(previous, b'+' | b'-' | b'.') {
                    start -= 1;
                } else {
                    break;
                }
            }

            let mut end = scheme_end + 3;
            while end < source.len() {
                let next = source.as_bytes()[end];
                if next.is_ascii_whitespace()
                    || matches!(next, b'"' | b'\'' | b'`' | b'<' | b'>' | b')' | b']')
                {
                    break;
                }
                end += 1;
            }

            links.push(source[start..end].to_owned());
            offset = end;
        }
        links
    }

    fn assert_resident_source_fixture_uses_generic_semantics(link: &str) {
        let lower = link.to_ascii_lowercase();
        let forbidden_terms = [
            ["matrix", "-"].concat(),
            ["invalid", "-", "test", "-", "format"].concat(),
        ];
        for forbidden in forbidden_terms {
            assert!(
                !lower.contains(&forbidden),
                "source fixture must use common import semantics, found {forbidden} in {link}"
            );
        }
        assert!(
            !link.contains('#'),
            "source fixture must not use fragment labels as matrix evidence: {link}"
        );
        if let Some(userinfo) = source_link_userinfo(link) {
            let lower_userinfo = userinfo.to_ascii_lowercase();
            for forbidden in ["matrix", "-password", "-auth"] {
                assert!(
                    !lower_userinfo.contains(forbidden),
                    "source fixture userinfo must be protocol-generic, found {forbidden} in {link}"
                );
            }
        }
    }

    fn source_link_userinfo(link: &str) -> Option<&str> {
        let authority = link.split_once("://")?.1;
        let authority = authority.split(['/', '?', '#']).next().unwrap_or(authority);
        authority.rsplit_once('@').map(|(userinfo, _)| userinfo)
    }

    fn parse_config(input: &str) -> Config {
        let sections = dae_config::parser::parse_config(input).unwrap();
        dae_config::schema::build_config(&sections).unwrap()
    }

    fn shadowsocks_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        ShadowsocksLink {
            name: String::new(),
            server: add.to_owned(),
            port,
            password: "password".to_owned(),
            cipher: "aes-128-gcm".to_owned(),
            plugin: Sip003::default(),
            udp: true,
            protocol: "shadowsocks".to_owned(),
        }
        .export_url()
    }

    fn shadowsocks_plugin_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        ShadowsocksLink {
            name: String::new(),
            server: add.to_owned(),
            port,
            password: "password".to_owned(),
            cipher: "aes-128-gcm".to_owned(),
            plugin: Sip003::parse("simple-obfs;obfs=http"),
            udp: false,
            protocol: "shadowsocks".to_owned(),
        }
        .export_url()
    }

    fn shadowsocks_simple_obfs_tls_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        ShadowsocksLink {
            name: String::new(),
            server: add.to_owned(),
            port,
            password: "password".to_owned(),
            cipher: "aes-128-gcm".to_owned(),
            plugin: Sip003::parse("simple-obfs;obfs=tls"),
            udp: false,
            protocol: "shadowsocks".to_owned(),
        }
        .export_url()
    }

    fn shadowsocks_v2ray_plugin_tls_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        format!(
            "ss://aes-128-gcm:password@{add}:{port}?plugin=v2ray-plugin%3Btls%3Bobfs-host%3Dfront.example%3Bobfs-uri%3D%2Fss"
        )
    }

    fn shadowsocks_2022_simple_obfs_http_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        format!(
            "ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng%3D%3D@{add}:{port}?plugin=simple-obfs%3Bobfs%3Dhttp%3Bobfs-host%3Dfront.example%3Bobfs-uri%3D%2F"
        )
    }

    fn shadowsocks_unsupported_plugin_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        format!("ss://aes-128-gcm:password@{add}:{port}?plugin=unknown-plugin")
    }

    fn vless_fixture_url(
        _ps: &str,
        add: &str,
        port: u16,
        net: &str,
        host: &str,
        path: &str,
        sni: &str,
        flow: &str,
        fingerprint: &str,
    ) -> String {
        VLESSLink {
            ps: String::new(),
            add: add.to_owned(),
            port: port.to_string(),
            id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
            net: net.to_owned(),
            r#type: "none".to_owned(),
            host: host.to_owned(),
            sni: sni.to_owned(),
            path: path.to_owned(),
            xhttp_mode: String::new(),
            xhttp_extra: String::new(),
            tls: "tls".to_owned(),
            flow: flow.to_owned(),
            alpn: String::new(),
            allow_insecure: false,
            fingerprint: fingerprint.to_owned(),
            public_key: String::new(),
            short_id: String::new(),
            spider_x: String::new(),
            protocol: "vless".to_owned(),
        }
        .export_url()
    }

    fn vless_xhttp_parser_fixture_url(mode: &str, alpn: &str, extra: &str) -> String {
        VLESSLink {
            ps: String::new(),
            add: "198.51.100.10".to_owned(),
            port: "443".to_owned(),
            id: "7c12c745-63a5-433d-9e60-022e469b5bd4".to_owned(),
            net: "xhttp".to_owned(),
            r#type: "none".to_owned(),
            host: "edge.transport.invalid".to_owned(),
            sni: "edge.transport.invalid".to_owned(),
            path: "/resource?ed=2048".to_owned(),
            xhttp_mode: mode.to_owned(),
            xhttp_extra: extra.to_owned(),
            tls: "tls".to_owned(),
            flow: String::new(),
            alpn: alpn.to_owned(),
            allow_insecure: false,
            fingerprint: String::new(),
            public_key: String::new(),
            short_id: String::new(),
            spider_x: String::new(),
            protocol: "vless".to_owned(),
        }
        .export_url()
    }

    fn trojan_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        TrojanLink {
            name: String::new(),
            server: add.to_owned(),
            port,
            password: "password".to_owned(),
            sni: "office.example".to_owned(),
            transport_type: String::new(),
            encryption: String::new(),
            host: String::new(),
            path: String::new(),
            service_name: String::new(),
            allow_insecure: false,
            protocol: "trojan".to_owned(),
        }
        .export_url()
    }

    fn trojan_websocket_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        TrojanLink {
            name: String::new(),
            server: add.to_owned(),
            port,
            password: "password".to_owned(),
            sni: "office.example".to_owned(),
            transport_type: "ws".to_owned(),
            encryption: String::new(),
            host: "front.example".to_owned(),
            path: "/trojan".to_owned(),
            service_name: String::new(),
            allow_insecure: false,
            protocol: "trojan-go".to_owned(),
        }
        .export_url()
    }

    fn trojan_httpupgrade_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        TrojanLink {
            name: String::new(),
            server: add.to_owned(),
            port,
            password: "password".to_owned(),
            sni: "office.example".to_owned(),
            transport_type: "httpupgrade".to_owned(),
            encryption: String::new(),
            host: "front.example".to_owned(),
            path: "/trojan-upgrade".to_owned(),
            service_name: String::new(),
            allow_insecure: false,
            protocol: "trojan-go".to_owned(),
        }
        .export_url()
    }

    fn trojan_grpc_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        TrojanLink {
            name: String::new(),
            server: add.to_owned(),
            port,
            password: "password".to_owned(),
            sni: "office.example".to_owned(),
            transport_type: "grpc".to_owned(),
            encryption: String::new(),
            host: "front.example".to_owned(),
            path: String::new(),
            service_name: "TrojanGunService".to_owned(),
            allow_insecure: false,
            protocol: "trojan-go".to_owned(),
        }
        .export_url()
    }

    fn hysteria2_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        hysteria2_fixture_url_with_pin("", &format!("{add}:{port}"), "AA-BB-CC")
    }

    fn hysteria2_fixture_url_with_pin(_ps: &str, server: &str, pin_sha256: &str) -> String {
        Hysteria2Link {
            name: String::new(),
            user: "auth-token".to_owned(),
            password: String::new(),
            server: server.to_owned(),
            insecure: false,
            sni: "office.example".to_owned(),
            pin_sha256: pin_sha256.to_owned(),
            max_tx: 0,
            max_rx: 0,
        }
        .export_url()
    }

    fn tuic_fixture_url(_ps: &str, add: &str, port: u16, allow_insecure: bool) -> String {
        TuicLink {
            name: String::new(),
            user: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
            password: "password".to_owned(),
            server: add.to_owned(),
            port,
            sni: "office.example".to_owned(),
            allow_insecure,
            disable_sni: false,
            congestion_control: String::new(),
            alpn: vec!["h3".to_owned()],
            udp_relay_mode: String::new(),
            protocol: "tuic".to_owned(),
        }
        .export_url()
    }

    fn juicity_fixture_url(_ps: &str, add: &str, port: u16, allow_insecure: bool) -> String {
        JuicityLink {
            name: String::new(),
            user: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
            password: "password".to_owned(),
            server: add.to_owned(),
            port,
            sni: "office.example".to_owned(),
            allow_insecure,
            congestion_control: String::new(),
            pinned_certchain_sha256: String::new(),
            protocol: "juicity".to_owned(),
        }
        .export_url()
    }

    fn vmess_fixture_url(
        _ps: &str,
        add: &str,
        port: u16,
        net: &str,
        host: &str,
        path: &str,
        tls: &str,
    ) -> String {
        vmess_fixture_url_with_sni(add, port, net, host, path, tls, "")
    }

    fn vmess_fixture_url_with_sni(
        add: &str,
        port: u16,
        net: &str,
        host: &str,
        path: &str,
        tls: &str,
        sni: &str,
    ) -> String {
        VMessLink {
            ps: String::new(),
            add: add.to_owned(),
            port: port.to_string(),
            id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
            aid: "0".to_owned(),
            net: net.to_owned(),
            r#type: "none".to_owned(),
            host: host.to_owned(),
            sni: sni.to_owned(),
            path: path.to_owned(),
            tls: tls.to_owned(),
            allow_insecure: false,
            fingerprint: String::new(),
            v: "2".to_owned(),
            protocol: "vmess".to_owned(),
        }
        .export_url()
    }

    fn vmess_legacy_fixture_url() -> String {
        "vmess://YXV0bzowMTIzNDU2Ny04OWFiLWNkZWYtMDEyMy00NTY3ODlhYmNkZWZAMjAzLjAuMTEzLjEwOjI4NDUy?alterId=0&obfs=tcp"
            .to_owned()
    }

    fn resident_admitted_source_fixture_links() -> Vec<String> {
        vec![
            "socks5://user:password@proxy.example.net:1080".to_owned(),
            "http://user:password@proxy.example.net:80".to_owned(),
            "https://user:password@secure-proxy.example.net:443".to_owned(),
            shadowsocks_fixture_url("ss", "203.0.113.10", 28446),
            shadowsocks_plugin_fixture_url("ss-plugin", "203.0.113.10", 28447),
            trojan_fixture_url("trojan", "203.0.113.10", 28444),
            trojan_websocket_fixture_url("trojan-ws", "203.0.113.10", 28456),
            "anytls://password@secure-stream.example.net:443?sni=secure-stream.example.net"
                .to_owned(),
            vmess_fixture_url("vmess", "203.0.113.10", 28452, "tcp", "", "", ""),
            vmess_fixture_url(
                "vmess-ws",
                "203.0.113.10",
                28454,
                "ws",
                "front.example",
                "/vmess",
                "",
            ),
            vmess_fixture_url_with_sni(
                "203.0.113.10",
                28454,
                "ws",
                "front.example",
                "/vmess",
                "tls",
                "office.example",
            ),
            vmess_fixture_url_with_sni(
                "203.0.113.10",
                28460,
                "httpupgrade",
                "front.example",
                "/vmess-upgrade",
                "tls",
                "office.example",
            ),
            vless_fixture_url(
                "vless-ws",
                "203.0.113.10",
                28443,
                "ws",
                "front.example",
                "/ws",
                "office.example",
                "",
                "",
            ),
            hysteria2_fixture_url("hy2", "203.0.113.10", 28453),
            hysteria2_fixture_url_with_pin("hy2-hop", "203.0.113.10:28453,28454-28455", "AA-BB-CC"),
            tuic_fixture_url("tuic", "203.0.113.10", 28454, true),
            tuic_fixture_url("tuic-verified", "203.0.113.10", 28454, false),
            juicity_fixture_url("juicity", "203.0.113.10", 28455, true),
        ]
    }

    fn assert_common_source_import_round_trips(link: &str) {
        let scheme = link
            .split_once("://")
            .map(|(scheme, _)| scheme)
            .unwrap_or_default();
        match scheme {
            "socks" | "socks5" => {
                let parsed = Url::parse(link).unwrap();
                assert!(parsed.has_host(), "{link}");
                assert!(parsed.port().is_some(), "{link}");
                assert!(!parsed.username().is_empty(), "{link}");
            }
            "http" | "https" => {
                assert_eq!(HttpProxyLink::parse(link).unwrap().export_url(), link);
            }
            "ss" => {
                assert_eq!(ShadowsocksLink::parse(link).unwrap().export_url(), link);
            }
            "trojan" | "trojan-go" => {
                assert_eq!(TrojanLink::parse(link).unwrap().export_url(), link);
            }
            "anytls" => {
                assert_eq!(AnyTLSLink::parse(link).unwrap().export_url(), link);
            }
            "vmess" => {
                assert_eq!(VMessLink::parse(link).unwrap().export_url(), link);
            }
            "vless" => {
                assert_eq!(VLESSLink::parse(link).unwrap().export_url(), link);
            }
            "hysteria2" | "hy2" => {
                assert_eq!(Hysteria2Link::parse(link).unwrap().export_url(), link);
            }
            "tuic" => {
                assert_eq!(TuicLink::parse(link).unwrap().export_url(), link);
            }
            "juicity" => {
                assert_eq!(JuicityLink::parse(link).unwrap().export_url(), link);
            }
            other => panic!("unexpected resident source fixture scheme {other}: {link}"),
        }
    }

    #[test]
    fn resident_admitted_source_fixtures_use_common_canonical_formats() {
        let links = resident_admitted_source_fixture_links();
        assert!(links.len() >= 10);
        for link in links {
            assert_resident_source_fixture_uses_generic_semantics(&link);
            assert_common_source_import_round_trips(&link);
        }
    }

    #[test]
    fn resident_legacy_import_normalizes_to_current_executor() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        routing {
        fallback: direct
        }
        "#,
        );
        let legacy = vmess_legacy_fixture_url();
        assert_resident_source_fixture_uses_generic_semantics(&legacy);
        let normalized = VMessLink::parse(&legacy).unwrap().export_url();
        assert_ne!(normalized, legacy);
        let proxy = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "legacy_import".to_owned(),
            legacy,
        )
        .unwrap();
        assert_eq!(proxy.protocol, "vmess");
        assert_eq!(proxy.net, "tcp");
        assert!(matches!(
            proxy.handler,
            ResidentProxyProtocolPlan::VmessAeadTcp { .. }
        ));
    }
