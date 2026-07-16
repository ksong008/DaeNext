use super::*;

fn fixture_config() -> Config {
    let sections = dae_config::parser::parse_config(
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
    )
    .unwrap();
    dae_config::schema::build_config(&sections).unwrap()
}

fn socks_source(authority: &str, passthrough_value: Option<&str>) -> String {
    let query = passthrough_value
        .map(|value| {
            format!(
                "?{}={value}",
                dae_outbound::shared_transport::contract::UDP_PASSTHROUGH_KEY
            )
        })
        .unwrap_or_default();
    format!("socks5://identity:credential@{authority}{query}")
}

fn build(source: String, node_tag: &str) -> Result<ResidentProxyPlan, String> {
    build_proxy_plan(
        &fixture_config(),
        "proxy".to_owned(),
        node_tag.to_owned(),
        source,
    )
}

#[test]
fn resident_source_admission_rejects_udp_passthrough_without_disclosing_source() {
    let source = socks_source("private-source.invalid:1080", Some("true"));
    let error = build(source.clone(), "passthrough-source").unwrap_err();

    assert!(error.contains(dae_outbound::shared_transport::contract::UDP_PASSTHROUGH_KEY));
    assert!(error.contains("fail-closed"));
    assert!(error.contains("passthrough-source"));
    assert!(!error.contains("identity"));
    assert!(!error.contains("credential"));
    assert!(!error.contains("private-source.invalid"));
    assert!(!error.contains(&source));
}

#[test]
fn resident_source_admission_checks_every_chain_node_for_udp_passthrough() {
    let ordinary_parent = socks_source("parent.invalid:1080", None);
    let ordinary_child = socks_source("child.invalid:1081", None);
    let requested_parent = socks_source("parent.invalid:1080", Some("TRUE"));
    let requested_child = socks_source("child.invalid:1081", Some("true"));

    for source in [
        format!("{requested_parent} -> {ordinary_child}"),
        format!("{ordinary_parent} -> {requested_child}"),
    ] {
        let error = build(source, "passthrough-chain").unwrap_err();
        assert!(error.contains("passthrough-chain"));
        assert!(error.contains("fail-closed"));
        assert!(!error.contains("parent.invalid"));
        assert!(!error.contains("child.invalid"));
    }
}

#[test]
fn resident_source_admission_preserves_unrequested_standalone_and_chain_builds() {
    let standalone = build(
        socks_source("standalone.invalid:1080", None),
        "ordinary-standalone",
    )
    .unwrap();
    assert!(standalone.chain_parent.is_none());

    let explicit_false = build(
        socks_source("explicit-false.invalid:1080", Some("false")),
        "explicit-false",
    )
    .unwrap();
    assert!(explicit_false.chain_parent.is_none());

    let chain = build(
        format!(
            "{} -> {}",
            socks_source("parent.invalid:1080", None),
            socks_source("child.invalid:1081", None),
        ),
        "ordinary-chain",
    )
    .unwrap();
    assert!(chain.chain_parent.is_some());
}
