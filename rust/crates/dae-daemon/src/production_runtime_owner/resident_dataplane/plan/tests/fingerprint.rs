#[test]
    fn resident_dataplane_plan_resolves_link_fingerprint_before_wire_gate() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        tls_implementation: utls
        utls_imitate: safari
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=firefox_105&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        let utls = proxy.utls_fingerprint.unwrap();
        assert_eq!(utls.source, "link fp");
        assert_eq!(utls.requested, "firefox_105");
        assert_eq!(utls.name, "firefox_105");
        assert_eq!(utls.family, "firefox");
    }

    #[test]
    fn resident_dataplane_plan_carries_generic_link_fingerprint() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=safari_16_0&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        assert!(plan.enabled);
        assert_eq!(proxy.node_tag, "vless_live");
        assert_eq!(proxy.flow, XTLS_RPRX_VISION);
        let utls = proxy.utls_fingerprint.unwrap();
        assert_eq!(utls.source, "link fp");
        assert_eq!(utls.requested, "safari_16_0");
        assert_eq!(utls.family, "safari");
    }

    #[test]
    fn resident_dataplane_plan_keeps_standard_tls_when_link_omits_fp_and_global_tls() {
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
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        assert!(proxy.utls_fingerprint.is_none());
    }

    #[test]
    fn resident_dataplane_plan_keeps_standard_tls_when_link_fp_is_empty_and_global_tls() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        assert!(proxy.utls_fingerprint.is_none());
    }

    #[test]
    fn resident_dataplane_plan_keeps_document_unsafe_auxiliary_rustls_path() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=unsafe&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        assert!(proxy.utls_fingerprint.is_none());
    }

    #[test]
    fn resident_dataplane_plan_uses_global_utls_when_link_does_not_set_fp() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        tls_implementation: utls
        utls_imitate: safari
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
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        let utls = proxy.utls_fingerprint.unwrap();
        assert_eq!(utls.source, "global utls_imitate");
        assert_eq!(utls.requested, "safari");
        assert_eq!(utls.canonical, "safari_auto");
        assert_eq!(utls.family, "safari");
    }

    #[test]
    fn resident_dataplane_plan_uses_global_utls_when_link_fp_is_empty() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        tls_implementation: utls
        utls_imitate: edge
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        let utls = proxy.utls_fingerprint.unwrap();
        assert_eq!(utls.source, "global utls_imitate");
        assert_eq!(utls.requested, "edge");
        assert_eq!(utls.canonical, "edge_auto");
        assert_eq!(utls.family, "edge");
    }

    #[test]
    fn resident_dataplane_plan_uses_document_default_when_global_utls_has_empty_imitate() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        tls_implementation: utls
        utls_imitate: ""
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
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        let utls = proxy.utls_fingerprint.unwrap();
        assert_eq!(utls.source, "default fingerprint");
        assert_eq!(utls.requested, "chrome");
        assert_eq!(utls.canonical, "chrome_auto");
        assert_eq!(utls.family, "chrome");
    }

    #[test]
    fn resident_dataplane_plan_rejects_unknown_utls_fingerprint() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=Chrome&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let err = build_resident_dataplane_plan(&config).unwrap_err();
        assert!(err.contains("unsupported link fp Chrome"));
        assert!(err.contains("unknown uTLS Client Hello ID: Chrome"));
    }

    #[test]
    fn resident_dataplane_plan_rejects_non_document_no_fingerprint_aliases() {
        for value in ["no", "none", "off", "false", "0"] {
            let config = parse_config(&format!(
                r#"
        global {{
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }}
        node {{
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp={value}&alpn=h2,http/1.1'
        }}
        group {{
        proxy {{
            filter: name(vless_live)
            policy: fixed(0)
        }}
        }}
        routing {{
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }}
        "#
            ));
            let err = build_resident_dataplane_plan(&config).unwrap_err();
            assert!(err.contains(&format!("unsupported link fp {value}")));
            assert!(err.contains(&format!("unknown uTLS Client Hello ID: {value}")));
        }
    }

    #[test]
    fn resident_utls_fingerprint_resolution_uses_generic_registry() {
        for (name, canonical, family) in [
            ("chrome", "chrome_auto", "chrome"),
            ("firefox_105", "firefox_105", "firefox"),
            ("safari_16_0", "safari_16_0", "safari"),
            ("ios_14", "ios_14", "ios"),
            ("edge_106", "edge_106", "edge"),
            ("android_11_okhttp", "android_11_okhttp", "android"),
            ("randomizednoalpn", "randomizednoalpn", "random"),
        ] {
            let plan = resolve_resident_utls_fingerprint("test", name).unwrap();
            assert_eq!(plan.name, name);
            assert_eq!(plan.canonical, canonical);
            assert_eq!(plan.family, family);
        }

        let randomized_no_alpn =
            resolve_resident_utls_fingerprint("test", "randomizednoalpn").unwrap();
        assert!(randomized_no_alpn.randomized);
        assert_eq!(randomized_no_alpn.alpn_policy, "force-no-alpn");
    }
