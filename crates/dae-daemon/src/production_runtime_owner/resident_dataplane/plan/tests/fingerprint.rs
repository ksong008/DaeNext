use super::*;

const XTLS_RPRX_VISION: &str = "xtls-rprx-vision";

fn fingerprint_config(global_tls_fields: &str, source: String) -> Config {
    fingerprint_config_with_mark(1234, global_tls_fields, source)
}

fn fingerprint_config_with_mark(mark: u32, global_tls_fields: &str, source: String) -> Config {
    let config_source = r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: __SO_MARK__
        mptcp: false
        __GLOBAL_TLS_FIELDS__
        }
        node {
        vless_live: '__SOURCE__'
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
        "#
    .replace("__SO_MARK__", &mark.to_string())
    .replace("__GLOBAL_TLS_FIELDS__", global_tls_fields)
    .replace("__SOURCE__", &source);
    parse_config(&config_source)
}

fn browser_default_alpn() -> Vec<String> {
    dae_outbound::shared_transport::UTLS_BROWSER_DEFAULT_ALPN
        .iter()
        .map(|protocol| (*protocol).to_owned())
        .collect()
}

fn default_proxy_for_source(global_tls_fields: &str, source: String) -> ResidentProxyPlan {
    let config = fingerprint_config(global_tls_fields, source);
    let plan = build_resident_dataplane_plan(&config).unwrap();
    plan.default_proxy_snapshot().unwrap()
}

#[test]
pub(super) fn resident_dataplane_plan_resolves_link_fingerprint_before_wire_gate() {
    let config = fingerprint_config(
        r#"
        tls_implementation: utls
        utls_imitate: safari
        "#,
        vless_vision_fixture_url("firefox_105"),
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
pub(super) fn resident_dataplane_plan_carries_generic_link_fingerprint() {
    let config = fingerprint_config("", vless_vision_fixture_url("safari_16_0"));
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
pub(super) fn resident_standard_tls_fingerprint_uses_browser_default_alpn_at_raw_tls_boundary() {
    let primary = fixture_host(FixtureEndpoint::Primary);
    let primary_port = fixture_port(FixtureEndpoint::Primary.slot());

    let mut vmess = VMessLink::parse(&vmess_fixture_url(
        "",
        &primary,
        primary_port,
        "tcp",
        "",
        "",
        "tls",
    ))
    .unwrap();
    vmess.fingerprint = "chrome_102".to_owned();

    let mut https_proxy =
        HttpProxyLink::parse(&https_proxy_fixture_url(&primary, primary_port)).unwrap();
    https_proxy.alpn.clear();
    https_proxy.utls_imitate = "chrome_102".to_owned();
    let mut https_proxy_link = https_proxy.export_url();
    let separator = if https_proxy_link.contains('?') {
        '&'
    } else {
        '?'
    };
    https_proxy_link.push(separator);
    https_proxy_link.push_str("utlsImitate=chrome_102");

    let http_1_1 = vec![dae_outbound::shared_transport::UTLS_ALPN_HTTP_1_1.to_owned()];
    for (label, proxy, expected_utls, expected_alpn) in [
        (
            "vless-tcp-link-fp",
            default_proxy_for_source("", vless_vision_without_flow_fixture_url("chrome_102")),
            true,
            browser_default_alpn(),
        ),
        (
            "vmess-tcp-link-fp",
            default_proxy_for_source("", vmess.export_url()),
            true,
            browser_default_alpn(),
        ),
        (
            "trojan-global-fp",
            default_proxy_for_source(
                r#"
                tls_implementation: utls
                utls_imitate: chrome_102
                "#,
                trojan_fixture_url("", &primary, primary_port),
            ),
            true,
            browser_default_alpn(),
        ),
        (
            "https-proxy-link-fp-empty-alpn",
            default_proxy_for_source("", https_proxy_link),
            true,
            http_1_1,
        ),
    ] {
        assert_eq!(proxy.tls, "tls", "{label}");
        assert_eq!(proxy.utls_fingerprint.is_some(), expected_utls, "{label}");
        assert_eq!(proxy.alpn, expected_alpn, "{label}");
    }
}

#[test]
pub(super) fn resident_standard_tls_fingerprint_keeps_protocol_required_or_explicit_alpn() {
    let primary = fixture_host(FixtureEndpoint::Primary);
    let primary_port = fixture_port(FixtureEndpoint::Primary.slot());

    let mut vmess_grpc = VMessLink::parse(&vmess_fixture_url(
        "",
        &primary,
        primary_port,
        "grpc",
        &fixture_host(FixtureEndpoint::Authority),
        "ServiceEndpoint",
        "tls",
    ))
    .unwrap();
    vmess_grpc.fingerprint = "chrome_102".to_owned();

    let mut vless_explicit = VLESSLink::parse(&vless_vision_fixture_url("chrome_102")).unwrap();
    vless_explicit.alpn = dae_outbound::shared_transport::UTLS_ALPN_HTTP_1_1.to_owned();

    for (label, proxy, expected_utls) in [
        (
            "vmess-grpc",
            default_proxy_for_source("", vmess_grpc.export_url()),
            true,
        ),
        (
            "trojan-grpc-global-fp-excluded",
            default_proxy_for_source(
                r#"
                tls_implementation: utls
                utls_imitate: chrome_102
                "#,
                trojan_grpc_fixture_url("", &primary, primary_port),
            ),
            false,
        ),
    ] {
        assert_eq!(proxy.tls, "tls", "{label}");
        assert_eq!(proxy.utls_fingerprint.is_some(), expected_utls, "{label}");
        assert_eq!(
            proxy.alpn,
            vec![dae_outbound::shared_transport::UTLS_ALPN_H2.to_owned()],
            "{label}"
        );
    }

    let explicit = default_proxy_for_source("", vless_explicit.export_url());
    assert_eq!(explicit.tls, "tls");
    assert!(explicit.utls_fingerprint.is_some());
    assert_eq!(
        explicit.alpn,
        vec![dae_outbound::shared_transport::UTLS_ALPN_HTTP_1_1.to_owned()]
    );
}

#[test]
pub(super) fn resident_global_utls_is_limited_to_raw_tls_boundaries() {
    let primary = fixture_host(FixtureEndpoint::Primary);
    let authority = fixture_host(FixtureEndpoint::Authority);
    let primary_port = fixture_port(FixtureEndpoint::Primary.slot());
    let global = r#"
        tls_implementation: utls
        utls_imitate: chrome_102
        "#;

    let vless_ws = vless_fixture_url(
        "",
        &primary,
        primary_port,
        "websocket",
        &authority,
        "/resource",
        &authority,
        "",
        "",
    );
    let vmess_ws = vmess_fixture_url_with_sni(
        &primary,
        primary_port,
        "ws",
        &authority,
        "/resource",
        "tls",
        &authority,
    );

    for (label, proxy) in [
        (
            "vless-websocket-global-excluded",
            default_proxy_for_source(global, vless_ws),
        ),
        (
            "vmess-websocket-global-excluded",
            default_proxy_for_source(global, vmess_ws),
        ),
        (
            "trojan-websocket-global-excluded",
            default_proxy_for_source(
                global,
                trojan_websocket_fixture_url("", &primary, primary_port),
            ),
        ),
        (
            "trojan-grpc-global-excluded",
            default_proxy_for_source(global, trojan_grpc_fixture_url("", &primary, primary_port)),
        ),
        (
            "anytls-global-excluded",
            default_proxy_for_source(global, anytls_fixture_url(&primary, primary_port)),
        ),
        (
            "https-proxy-global-excluded",
            default_proxy_for_source(global, https_proxy_fixture_url(&primary, primary_port)),
        ),
    ] {
        assert_eq!(proxy.tls, "tls", "{label}");
        assert!(proxy.utls_fingerprint.is_none(), "{label}");
    }
}

#[test]
pub(super) fn resident_dataplane_plan_carries_reality_link_fingerprint_without_losing_reality() {
    let config = fingerprint_config("", vless_reality_fixture_url_with_fingerprint("ios_14"));
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let proxy = plan.default_proxy_snapshot().unwrap();
    assert!(plan.enabled);
    assert_eq!(proxy.node_tag, "vless_live");
    assert_eq!(proxy.tls, "reality");
    assert_eq!(proxy.flow, XTLS_RPRX_VISION);
    assert!(proxy.reality.is_some());
    let utls = proxy.utls_fingerprint.as_ref().unwrap();
    assert_eq!(utls.source, "link fp");
    assert_eq!(utls.requested, "ios_14");
    assert_eq!(utls.family, "ios");
    assert_eq!(utls.default_alpn, browser_default_alpn());
    assert_eq!(proxy.alpn, utls.default_alpn);

    let graph = proxy.executable_graph_value();
    assert_eq!(graph["securityUnderlay"], "reality");
    assert_eq!(graph["admission"]["status"], "admitted");
    let underlay = &graph["runtimeComponents"]["underlayFactory"];
    assert_eq!(underlay["status"], "admitted");
    assert_eq!(underlay["provider"], "reality-boringssl");
    assert_eq!(underlay["securityUnderlay"], "reality");
    assert!(underlay["unsupportedReason"].is_null());
    assert_eq!(underlay["fingerprint"]["requested"], "ios_14");
    assert_eq!(underlay["fingerprint"]["family"], "ios");
}

#[test]
pub(super) fn resident_dataplane_plan_rejects_unknown_reality_link_fingerprint() {
    let config = fingerprint_config("", vless_reality_fixture_url_with_fingerprint("Chrome"));
    let err = build_resident_dataplane_plan(&config).unwrap_err();
    assert!(err.contains("unsupported link fp Chrome"));
    assert!(err.contains("unknown uTLS Client Hello ID: Chrome"));
}

#[test]
pub(super) fn latency_probe_helper_preserves_fingerprint_and_adds_control_mark_when_config_mark_is_zero()
 {
    let link = vless_vision_fixture_url("chrome");
    let config = fingerprint_config_with_mark(0, "", link.clone());
    let normal_plans = build_resident_manual_probe_plans(&config);
    let normal = normal_plans.get(&link).unwrap().as_ref().unwrap();
    assert_eq!(normal.proxy.mark, 0);
    assert!(normal.proxy.utls_fingerprint.is_some());

    let helper_plans = build_resident_manual_probe_plans_for_helper(&config);
    let helper = helper_plans.get(&link).unwrap().as_ref().unwrap();
    assert_eq!(helper.proxy.mark, RESIDENT_CONTROL_PLANE_SO_MARK);
    let utls = helper.proxy.utls_fingerprint.as_ref().unwrap();
    assert_eq!(utls.source, "link fp");
    assert_eq!(utls.requested, "chrome");
}

#[test]
pub(super) fn latency_probe_helper_preserves_reality_fingerprint_and_adds_control_mark_when_config_mark_is_zero()
 {
    let link = vless_reality_fixture_url_with_fingerprint("safari_16_0");
    let config = fingerprint_config_with_mark(0, "", link.clone());
    let normal_plans = build_resident_manual_probe_plans(&config);
    let normal = normal_plans.get(&link).unwrap().as_ref().unwrap();
    assert_eq!(normal.proxy.mark, 0);
    assert_eq!(normal.proxy.tls, "reality");
    assert!(normal.proxy.reality.is_some());
    assert!(normal.proxy.utls_fingerprint.is_some());

    let helper_plans = build_resident_manual_probe_plans_for_helper(&config);
    let helper = helper_plans.get(&link).unwrap().as_ref().unwrap();
    assert_eq!(helper.proxy.mark, RESIDENT_CONTROL_PLANE_SO_MARK);
    assert_eq!(helper.proxy.tls, "reality");
    let utls = helper.proxy.utls_fingerprint.as_ref().unwrap();
    assert_eq!(utls.source, "link fp");
    assert_eq!(utls.requested, "safari_16_0");
}

#[test]
pub(super) fn resident_dataplane_plan_keeps_standard_tls_when_link_omits_fp_and_global_tls() {
    let config = fingerprint_config("", vless_vision_fixture_url(""));
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let proxy = plan.default_proxy_snapshot().unwrap();
    assert!(proxy.utls_fingerprint.is_none());
}

#[test]
pub(super) fn resident_dataplane_plan_keeps_standard_tls_when_link_fp_is_empty_and_global_tls() {
    let config = fingerprint_config("", vless_vision_empty_fingerprint_fixture_url());
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let proxy = plan.default_proxy_snapshot().unwrap();
    assert!(proxy.utls_fingerprint.is_none());
}

#[test]
pub(super) fn resident_dataplane_plan_keeps_document_unsafe_auxiliary_rustls_path() {
    let config = fingerprint_config("", vless_vision_fixture_url("unsafe"));
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let proxy = plan.default_proxy_snapshot().unwrap();
    assert!(proxy.utls_fingerprint.is_none());
}

#[test]
pub(super) fn resident_dataplane_plan_fp_unsafe_blocks_global_utls_fallback() {
    let config = fingerprint_config(
        r#"
        tls_implementation: utls
        utls_imitate: safari
        "#,
        vless_vision_fixture_url("unsafe"),
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let proxy = plan.default_proxy_snapshot().unwrap();
    assert!(proxy.utls_fingerprint.is_none());
}

#[test]
pub(super) fn resident_dataplane_plan_uses_global_utls_when_link_does_not_set_fp() {
    let config = fingerprint_config(
        r#"
        tls_implementation: utls
        utls_imitate: safari
        "#,
        vless_vision_fixture_url(""),
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
pub(super) fn resident_dataplane_plan_uses_global_utls_when_link_fp_is_empty() {
    let config = fingerprint_config(
        r#"
        tls_implementation: utls
        utls_imitate: edge
        "#,
        vless_vision_empty_fingerprint_fixture_url(),
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
pub(super) fn resident_dataplane_plan_uses_document_default_when_global_utls_has_empty_imitate() {
    let config = fingerprint_config(
        r#"
        tls_implementation: utls
        utls_imitate: ""
        "#,
        vless_vision_fixture_url(""),
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
pub(super) fn resident_dataplane_plan_rejects_unknown_utls_fingerprint() {
    let config = fingerprint_config("", vless_vision_fixture_url("Chrome"));
    let err = build_resident_dataplane_plan(&config).unwrap_err();
    assert!(err.contains("unsupported link fp Chrome"));
    assert!(err.contains("unknown uTLS Client Hello ID: Chrome"));
}

#[test]
pub(super) fn resident_dataplane_plan_rejects_non_document_no_fingerprint_aliases() {
    for value in ["no", "none", "off", "false", "0"] {
        let config = fingerprint_config("", vless_vision_fixture_url(value));
        let err = build_resident_dataplane_plan(&config).unwrap_err();
        assert!(err.contains(&format!("unsupported link fp {value}")));
        assert!(err.contains(&format!("unknown uTLS Client Hello ID: {value}")));
    }
}

#[test]
pub(super) fn resident_utls_fingerprint_resolution_uses_generic_registry() {
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

    let randomized_no_alpn = resolve_resident_utls_fingerprint("test", "randomizednoalpn").unwrap();
    assert!(randomized_no_alpn.randomized);
    assert_eq!(
        randomized_no_alpn.alpn_policy,
        dae_outbound::shared_transport::UTLS_ALPN_POLICY_RANDOMIZED_NO_ALPN
    );
    assert!(randomized_no_alpn.default_alpn.is_empty());
}

#[test]
pub(super) fn resident_reality_alpn_defaults_follow_fingerprint_registry_without_link_alpn() {
    for (fingerprint, expected) in [
        (
            "chrome",
            dae_outbound::shared_transport::UTLS_BROWSER_DEFAULT_ALPN.to_vec(),
        ),
        (
            "ios",
            dae_outbound::shared_transport::UTLS_BROWSER_DEFAULT_ALPN.to_vec(),
        ),
        (
            "safari",
            dae_outbound::shared_transport::UTLS_BROWSER_DEFAULT_ALPN.to_vec(),
        ),
        ("randomizednoalpn", Vec::<&str>::new()),
        ("android_11_okhttp", Vec::<&str>::new()),
    ] {
        let mut link =
            VLESSLink::parse(&vless_reality_fixture_url_with_fingerprint(fingerprint)).unwrap();
        link.alpn.clear();
        let config = fingerprint_config("", link.export_url());
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        let expected = expected.into_iter().map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(proxy.alpn, expected, "fingerprint={fingerprint}");
    }
}

#[test]
pub(super) fn resident_reality_keeps_explicit_link_alpn_over_fingerprint_default() {
    let mut link = VLESSLink::parse(&vless_reality_fixture_url_with_fingerprint("chrome")).unwrap();
    link.alpn = dae_outbound::shared_transport::UTLS_ALPN_HTTP_1_1.to_owned();
    let config = fingerprint_config("", link.export_url());
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let proxy = plan.default_proxy_snapshot().unwrap();

    assert_eq!(
        proxy.alpn,
        vec![dae_outbound::shared_transport::UTLS_ALPN_HTTP_1_1.to_owned()]
    );
}
