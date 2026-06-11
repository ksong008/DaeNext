use super::*;

fn fingerprint_config(global_tls_fields: &str, source: String) -> Config {
    let config_source = r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
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
    .replace("__GLOBAL_TLS_FIELDS__", global_tls_fields)
    .replace("__SOURCE__", &source);
    parse_config(&config_source)
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
    assert_eq!(randomized_no_alpn.alpn_policy, "force-no-alpn");
}
