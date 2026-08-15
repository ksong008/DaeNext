use super::*;

const XHTTP_H3_NODE_TAG: &str = "xhttp_h3_quic_tls";
const XHTTP_H3_FINGERPRINT: &str = "chrome_102";
const XHTTP_H3_ALPN: &str = "h3";
const XHTTP_DOWNLOAD_PORT: u16 = 18_444;
const REALITY_PUBLIC_KEY_LEN: usize = 32;

const XHTTP_H3_DEFAULT_CONFIG: &str = r#"
global {
lan_interface: daerust0
allow_insecure: false
so_mark_from_dae: 1234
mptcp: false
}
routing {
fallback: direct
}
"#;

const XHTTP_H3_INSECURE_CONFIG: &str = r#"
global {
lan_interface: daerust0
allow_insecure: true
so_mark_from_dae: 1234
mptcp: false
}
routing {
fallback: direct
}
"#;

const XHTTP_H3_FRAGMENT_CONFIG: &str = r#"
global {
lan_interface: daerust0
allow_insecure: false
so_mark_from_dae: 1234
mptcp: false
tls_fragment: true
tls_fragment_length: 1-4
tls_fragment_interval: 1-1
}
routing {
fallback: direct
}
"#;

#[test]
fn xhttp_h3_execution_uses_quic_tls_without_opening_a_network_owner() {
    for (config_source, verification_policy) in [
        (XHTTP_H3_DEFAULT_CONFIG, "system-roots"),
        (XHTTP_H3_INSECURE_CONFIG, "explicit-insecure"),
    ] {
        let proxy = build_resident_proxy_plan_for_node(
            &parse_config(config_source),
            "proxy".to_owned(),
            XHTTP_H3_NODE_TAG.to_owned(),
            vless_xhttp_parser_fixture_url("packet-up", XHTTP_H3_ALPN, ""),
        )
        .unwrap();
        let execution = proxy.execution_plan();

        assert_eq!(execution.security, ResidentSecurityUnderlayPlan::QuicTls);
        assert_eq!(
            execution.wrapper,
            ResidentStreamWrapperPlan::Xhttp(ResidentXhttpHttpVersion::H3)
        );
        assert_eq!(
            execution.udp,
            ResidentUdpExecutorFactory::VlessStandard(ResidentStreamPacketTransport::XhttpH3)
        );

        let graph = proxy.executable_graph_value();
        assert_eq!(graph["transportUnderlay"], "quic");
        assert_eq!(graph["securityUnderlay"], "quic-tls");
        assert_eq!(
            graph["runtimeComponents"]["underlayFactory"]["provider"],
            expected_resident_quic_provider()
        );
        assert_eq!(
            graph["runtimeComponents"]["underlayFactory"]["verificationPolicy"],
            verification_policy
        );
        assert_eq!(
            graph["runtimeComponents"]["underlayFactory"]["sessionPolicy"],
            serde_json::json!({
                "resumption": "quic-session-cache",
                "cacheScope": if cfg!(feature = "test-boringssl-quic") {
                    "reload-generation"
                } else {
                    "provider-config"
                },
                "zeroRtt": false,
            })
        );
        let lifecycle = &graph["runtimeComponents"]["underlayFactory"]["quicLifecycle"];
        assert_eq!(
            lifecycle["endpointScope"],
            "generation-graph-transport-owner"
        );
        assert_eq!(
            lifecycle["connectionScope"],
            "generation-graph-transport-owner"
        );
        assert_eq!(lifecycle["clientConfigScope"], "physical-transport-owner");
        assert_eq!(lifecycle["crossFlowConnectionReuse"], true);
        assert_eq!(
            graph["runtimeComponents"]["generationCache"]["sharedProviderCaches"]
                .as_array()
                .unwrap()
                .iter()
                .any(|provider| provider == "quic-session-cache"),
            cfg!(feature = "test-boringssl-quic")
        );
        assert_eq!(
            graph["runtimeComponents"]["generationCache"]["perFlowProviders"],
            serde_json::json!([])
        );
        assert_eq!(graph["admission"]["status"], "admitted");
    }
}

#[test]
fn xhttp_h3_xmux_evidence_matches_provider_session_cache_ownership() {
    let extra = r#"{"xmux":{"maxConnections":2}}"#;
    let proxy = build_resident_proxy_plan_for_node(
        &parse_config(XHTTP_H3_DEFAULT_CONFIG),
        "proxy".to_owned(),
        XHTTP_H3_NODE_TAG.to_owned(),
        vless_xhttp_parser_fixture_url("packet-up", XHTTP_H3_ALPN, extra),
    )
    .unwrap();
    let graph = proxy.executable_graph_value();
    let lifecycle = &graph["runtimeComponents"]["underlayFactory"]["quicLifecycle"];
    assert_eq!(
        lifecycle["endpointScope"],
        "generation-graph-transport-owner"
    );
    assert_eq!(
        lifecycle["connectionScope"],
        "generation-graph-transport-owner"
    );
    assert_eq!(lifecycle["crossFlowConnectionReuse"], true);
    assert_eq!(
        graph["runtimeComponents"]["underlayFactory"]["sessionPolicy"]["cacheScope"],
        if cfg!(feature = "test-boringssl-quic") {
            "reload-generation"
        } else {
            "provider-config"
        }
    );
    assert_eq!(
        graph["runtimeComponents"]["generationCache"]["sharedProviderCaches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|provider| provider == "quic-session-cache"),
        cfg!(feature = "test-boringssl-quic")
    );
    assert_eq!(
        graph["runtimeComponents"]["generationCache"]["perFlowProviders"],
        serde_json::json!([])
    );

    let mut chrome_link = VLESSLink::parse(&vless_xhttp_parser_fixture_url(
        "packet-up",
        XHTTP_H3_ALPN,
        extra,
    ))
    .unwrap();
    chrome_link.fingerprint = "chrome".to_owned();
    let chrome = build_resident_proxy_plan_for_node(
        &parse_config(XHTTP_H3_DEFAULT_CONFIG),
        "proxy".to_owned(),
        "xhttp_h3_chrome_xmux".to_owned(),
        chrome_link.export_url(),
    )
    .unwrap();
    let chrome_graph = chrome.executable_graph_value();
    assert_eq!(
        chrome_graph["runtimeComponents"]["underlayFactory"]["provider"],
        "quinn-boringssl-chrome"
    );
    assert_eq!(
        chrome_graph["runtimeComponents"]["underlayFactory"]["sessionPolicy"],
        serde_json::json!({
            "resumption": "quic-session-cache",
            "cacheScope": "reload-generation",
            "zeroRtt": false,
        })
    );
    assert!(
        chrome_graph["runtimeComponents"]["generationCache"]["sharedProviderCaches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|provider| provider == "quic-session-cache")
    );
}

#[test]
fn xhttp_h3_does_not_attach_global_tcp_tls_fragmentation() {
    let proxy = build_resident_proxy_plan_for_node(
        &parse_config(XHTTP_H3_FRAGMENT_CONFIG),
        "proxy".to_owned(),
        XHTTP_H3_NODE_TAG.to_owned(),
        vless_xhttp_parser_fixture_url("packet-up", XHTTP_H3_ALPN, ""),
    )
    .unwrap();

    assert!(proxy.tls_fragment.is_none());
    assert_eq!(
        proxy.execution_plan().security,
        ResidentSecurityUnderlayPlan::QuicTls
    );
}

#[test]
fn xhttp_h3_rejects_non_chrome_auto_fingerprint_before_execution() {
    let source = vless_xhttp_parser_fixture_url("packet-up", XHTTP_H3_ALPN, "");
    let mut link = VLESSLink::parse(&source).unwrap();
    link.fingerprint = XHTTP_H3_FINGERPRINT.to_owned();

    let error = build_resident_proxy_plan_for_node(
        &parse_config(XHTTP_H3_DEFAULT_CONFIG),
        "proxy".to_owned(),
        XHTTP_H3_NODE_TAG.to_owned(),
        link.export_url(),
    )
    .unwrap_err();

    assert!(
        error.contains("supports only chrome/chrome_auto fingerprint"),
        "{error}"
    );
}

#[test]
fn xhttp_h3_rejects_reality_download_endpoint_before_execution() {
    let public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode([FixtureEndpoint::Secondary.slot() as u8; REALITY_PUBLIC_KEY_LEN]);
    let extra = format!(
        r#"{{"downloadSettings":{{"address":"download.transport.invalid","port":{XHTTP_DOWNLOAD_PORT},"network":"xhttp","security":"reality","realitySettings":{{"serverName":"download.sni.invalid","alpn":["h3"],"publicKey":"{public_key}","shortId":"01020304","spiderX":"/download"}},"xhttpSettings":{{"host":"download.host.invalid","path":"/down","mode":"packet-up"}}}}}}"#
    );

    let error = build_resident_proxy_plan_for_node(
        &parse_config(XHTTP_H3_DEFAULT_CONFIG),
        "proxy".to_owned(),
        XHTTP_H3_NODE_TAG.to_owned(),
        vless_xhttp_parser_fixture_url("packet-up", "h2", &extra),
    )
    .unwrap_err();

    assert!(
        error.contains("downloadSettings.security=reality"),
        "{error}"
    );
    assert!(
        error.contains("QUIC TLS carrier has no Reality executor"),
        "{error}"
    );
}
