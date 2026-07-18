use super::*;

const XHTTP_H3_ALPN: &str = "h3";
const XHTTP_H3_UNSUPPORTED_FINGERPRINT: &str = "chrome_102";
const REALITY_PUBLIC_KEY_LEN: usize = 32;

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

fn build_with_config(config: &str, source: String) -> Result<ResidentProxyPlan, String> {
    build_resident_proxy_plan_for_node(
        &parse_config(config),
        "proxy".to_owned(),
        "xhttp-h3-source-shape".to_owned(),
        source,
    )
}

#[test]
fn builder_xhttp_h3_materializes_quic_tls_and_normalizes_global_fragment() {
    let source = vless_xhttp_parser_fixture_url("packet-up", XHTTP_H3_ALPN, "");
    for (config, verification) in [
        (
            XHTTP_H3_FRAGMENT_CONFIG,
            MaterializedQuicVerification::WebPki,
        ),
        (
            XHTTP_H3_INSECURE_CONFIG,
            MaterializedQuicVerification::Insecure,
        ),
    ] {
        let proxy = build_with_config(config, source.clone()).unwrap();
        let shape = materialized_source_shape(&proxy, &source);
        assert_eq!(shape.security, MaterializedSecurity::QuicTls);
        assert_eq!(shape.tls_features, MaterializedTlsFeatures::NONE);
        assert_eq!(shape.quic_verification, verification);
        assert!(proxy.tls_fragment.is_none());
        assert!(
            source_shape_reconciliation("xhttp-h3-wrapper")
                .unwrap()
                .matches(shape)
        );
    }
}

#[test]
fn builder_xhttp_h3_admits_only_chrome_auto_fingerprint_provider() {
    let source = vless_xhttp_parser_fixture_url("packet-up", XHTTP_H3_ALPN, "");
    for fingerprint in ["chrome", "chrome_auto"] {
        let mut link = VLESSLink::parse(&source).unwrap();
        link.fingerprint = fingerprint.to_owned();
        let proxy = build(&link.export_url()).unwrap();
        assert_eq!(
            ResidentXhttpQuicTlsProvider::for_primary(proxy.utls_fingerprint.as_ref()).unwrap(),
            ResidentXhttpQuicTlsProvider::ChromeBoring
        );
    }
}

#[test]
fn builder_xhttp_h3_rejects_other_fingerprints() {
    let source = vless_xhttp_parser_fixture_url("packet-up", XHTTP_H3_ALPN, "");
    let mut link = VLESSLink::parse(&source).unwrap();
    link.fingerprint = XHTTP_H3_UNSUPPORTED_FINGERPRINT.to_owned();

    let error = build(&link.export_url()).unwrap_err();
    assert!(
        error.contains("supports only chrome/chrome_auto fingerprint"),
        "{error}"
    );
}

#[test]
fn builder_xhttp_h3_rejects_reality_download_endpoint() {
    let public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode([FixtureEndpoint::Secondary.slot() as u8; REALITY_PUBLIC_KEY_LEN]);
    let download_port = fixture_port(9);
    let extra = format!(
        r#"{{"downloadSettings":{{"address":"download.transport.invalid","port":{download_port},"network":"xhttp","security":"reality","realitySettings":{{"serverName":"download.sni.invalid","alpn":["h3"],"publicKey":"{public_key}","shortId":"01020304","spiderX":"/download"}},"xhttpSettings":{{"host":"download.host.invalid","path":"/down","mode":"packet-up"}}}}}}"#
    );

    let error = build(&vless_xhttp_parser_fixture_url("packet-up", "h2", &extra)).unwrap_err();
    assert!(
        error.contains("downloadSettings.security=reality"),
        "{error}"
    );
    assert!(
        error.contains("QUIC TLS carrier has no Reality executor"),
        "{error}"
    );
}
