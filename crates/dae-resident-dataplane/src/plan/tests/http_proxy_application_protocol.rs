use super::*;

fn config() -> Config {
    parse_config(
        r#"
        global {
            lan_interface: daerust0
        }
        routing {
            fallback: direct
        }
        "#,
    )
}

#[test]
fn https_proxy_plan_advertises_only_http1() {
    let host = fixture_host(FixtureEndpoint::Primary);
    let port = fixture_port(1);
    let source = format!("https://{host}:{port}?alpn=h2,http%2F1.1");
    let proxy = build_resident_proxy_plan_for_node(
        &config(),
        "proxy".to_owned(),
        "https_mixed_alpn".to_owned(),
        source,
    )
    .unwrap();

    assert_eq!(proxy.alpn, [dae_outbound::http_proxy::HTTP_1_1_ALPN]);
}

#[test]
fn https_proxy_plan_rejects_h2_only_before_runtime_construction() {
    let host = fixture_host(FixtureEndpoint::Primary);
    let port = fixture_port(1);
    let source = format!("https://{host}:{port}?alpn=h2");
    let error = build_resident_proxy_plan_for_node(
        &config(),
        "proxy".to_owned(),
        "https_h2_only".to_owned(),
        source,
    )
    .unwrap_err();

    assert!(error.contains("no supported ALPN"), "{error}");
}
