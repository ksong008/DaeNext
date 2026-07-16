use dae_outbound::{
    MaterializedPolicyClosedReason, MaterializedProtocol, MaterializedStreamPacketTransport,
    MaterializedUdp, MaterializedWrapper, SourceShapeReconciliationKind,
};

use super::*;

const TROJAN_SCHEME: &str = "trojan";
const TROJAN_GO_SCHEME: &str = "trojan-go";
const HTTPUPGRADE_TRANSPORT: &str = "httpupgrade";
const WEBSOCKET_TRANSPORT: &str = "ws";
const RESOURCE_PATH_QUERY_VALUE: &str = "%2Fresource";
const CANDIDATE_NODE_TAG: &str = "trojan-scheme-alias";
const HTTPUPGRADE_SHAPE_ID: &str = "stream-wrapper-httpupgrade";
const INNER_ENCRYPTION_SHAPE_ID: &str = "inner-encryption-stream-wrapper";
const INNER_ENCRYPTION_CIPHER: &str = "aes-128-gcm";

fn raw_trojan_source(scheme: &str, transport: &str, encryption: Option<&str>) -> String {
    let encryption_query = encryption
        .map(|value| format!("&encryption={value}"))
        .unwrap_or_default();
    format!(
        "{scheme}://{}@{}:{}?security=tls&sni={}&type={transport}&host={}&path={RESOURCE_PATH_QUERY_VALUE}{encryption_query}",
        fixture_secret(),
        fixture_host(FixtureEndpoint::Primary),
        fixture_endpoint_port(FixtureEndpoint::Tertiary),
        fixture_host(FixtureEndpoint::Authority),
        fixture_host(FixtureEndpoint::Authority),
    )
}

fn raw_inner_encryption_source(scheme: &str) -> String {
    raw_trojan_source(
        scheme,
        WEBSOCKET_TRANSPORT,
        Some(&format!(
            "ss%3B{INNER_ENCRYPTION_CIPHER}%3A{}",
            fixture_secret()
        )),
    )
}

fn row(shape_id: &str) -> &'static dae_outbound::SourceShapeRegistryRow {
    dae_outbound::source_shape_registry_rows()
        .iter()
        .find(|row| row.shape_id == shape_id)
        .unwrap_or_else(|| panic!("missing source registry row: {shape_id}"))
}

fn candidate_node(source: &str, expected_scheme: &str) -> ResidentNodeLinkShape {
    let parsed = dae_outbound::parse_link_chain(source).expect("raw Trojan source must parse");
    let parsed_scheme = parsed
        .nodes
        .first()
        .expect("raw Trojan source must contain one node")
        .scheme
        .clone();
    assert_eq!(parsed.nodes.len(), 1);
    assert_eq!(parsed_scheme, expected_scheme);
    ResidentNodeLinkShape {
        tag: CANDIDATE_NODE_TAG.to_owned(),
        scheme: parsed_scheme,
        link: source.to_owned(),
    }
}

fn assert_candidate_and_single_selector_match(
    shape_id: &str,
    scheme: &str,
    source: &str,
) -> dae_outbound::MaterializedSourceShape {
    let row = row(shape_id);
    let proxy = build(source).unwrap_or_else(|error| panic!("build {shape_id}: {error}"));
    let node = candidate_node(source, scheme);
    assert!(source_shape_candidate_is_relevant(row, &node));
    assert!(source_shape_matches_materialization(row, &proxy, source));

    let materialized = materialized_source_shape(&proxy, source);
    let reconciliation = source_shape_reconciliation(shape_id).unwrap();
    assert_eq!(
        reconciliation.kind,
        SourceShapeReconciliationKind::ProductionWitness
    );
    assert_eq!(
        reconciliation
            .selectors
            .iter()
            .filter(|selector| selector.matches(materialized))
            .count(),
        1,
        "{shape_id} must select one exact production shape for {scheme}"
    );
    materialized
}

#[test]
fn raw_trojan_httpupgrade_reaches_the_trojan_production_selector() {
    for scheme in [TROJAN_SCHEME, TROJAN_GO_SCHEME] {
        let source = raw_trojan_source(scheme, HTTPUPGRADE_TRANSPORT, None);
        let materialized =
            assert_candidate_and_single_selector_match(HTTPUPGRADE_SHAPE_ID, scheme, &source);
        assert_eq!(materialized.protocol, MaterializedProtocol::Trojan);
        assert_eq!(materialized.wrapper, MaterializedWrapper::HttpUpgrade);
        assert_eq!(
            materialized.udp,
            MaterializedUdp::Trojan(MaterializedStreamPacketTransport::HttpUpgradeTls)
        );
    }
}

#[test]
fn raw_trojan_inner_encryption_reaches_only_the_inner_production_selector() {
    for scheme in [TROJAN_SCHEME, TROJAN_GO_SCHEME] {
        let source = raw_inner_encryption_source(scheme);
        let materialized =
            assert_candidate_and_single_selector_match(INNER_ENCRYPTION_SHAPE_ID, scheme, &source);
        assert_eq!(
            materialized.protocol,
            MaterializedProtocol::TrojanInnerShadowsocks
        );
        assert_eq!(materialized.wrapper, MaterializedWrapper::WebSocket);
        assert_eq!(
            materialized.udp,
            MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::TrojanInnerShadowsocks)
        );
    }

    let ordinary = raw_trojan_source(TROJAN_SCHEME, WEBSOCKET_TRANSPORT, None);
    let ordinary_proxy = build(&ordinary).unwrap();
    let ordinary_shape = materialized_source_shape(&ordinary_proxy, &ordinary);
    let inner_row = row(INNER_ENCRYPTION_SHAPE_ID);
    assert!(source_shape_candidate_is_relevant(
        inner_row,
        &candidate_node(&ordinary, TROJAN_SCHEME)
    ));
    assert_eq!(ordinary_shape.protocol, MaterializedProtocol::Trojan);
    assert!(
        !source_shape_reconciliation(INNER_ENCRYPTION_SHAPE_ID)
            .unwrap()
            .matches(ordinary_shape)
    );
    assert!(!source_shape_matches_materialization(
        inner_row,
        &ordinary_proxy,
        &ordinary,
    ));
}
