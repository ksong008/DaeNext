use super::*;

#[test]
fn builder_qualifiers_isolate_hy2_port_hopping_and_tuic_verification() {
    let primary = fixture_host(FixtureEndpoint::Primary);
    let ordinary = hysteria2_fixture_url("", &primary, fixture_port(4));
    let ordinary_proxy = build(&ordinary).unwrap();
    let ordinary_shape = materialized_source_shape(&ordinary_proxy, &ordinary);
    assert_eq!(
        ordinary_shape.port_hopping,
        MaterializedPortHopping::Disabled
    );
    assert!(
        source_shape_reconciliation("baseline-quic-auth-endpoint")
            .unwrap()
            .matches(ordinary_shape)
    );
    assert!(
        !source_shape_reconciliation("quic-port-hopping-surface")
            .unwrap()
            .matches(ordinary_shape)
    );

    let hopping = hysteria2_fixture_url_with_pin(
        "",
        &fixture_hop_server(
            fixture_port(4),
            &format!(",{}-{}", fixture_port(5), fixture_port(7)),
        ),
        &fixture_pin_sha256(),
    );
    let hopping_proxy = build(&hopping).unwrap();
    let hopping_shape = materialized_source_shape(&hopping_proxy, &hopping);
    assert_eq!(hopping_shape.port_hopping, MaterializedPortHopping::Enabled);
    assert!(
        source_shape_reconciliation("quic-port-hopping-surface")
            .unwrap()
            .matches(hopping_shape)
    );

    let verified = tuic_fixture_url("", &primary, fixture_port(8), false);
    let verified_proxy = build(&verified).unwrap();
    let verified_shape = materialized_source_shape(&verified_proxy, &verified);
    assert_eq!(
        verified_shape.quic_verification,
        MaterializedQuicVerification::WebPki
    );
    assert!(
        source_shape_reconciliation("verified-quic-security-underlay")
            .unwrap()
            .matches(verified_shape)
    );

    let insecure = tuic_fixture_url("", &primary, fixture_port(8), true);
    let insecure_proxy = build(&insecure).unwrap();
    let insecure_shape = materialized_source_shape(&insecure_proxy, &insecure);
    assert_eq!(
        insecure_shape.quic_verification,
        MaterializedQuicVerification::Insecure
    );
    assert!(
        !source_shape_reconciliation("verified-quic-security-underlay")
            .unwrap()
            .matches(insecure_shape)
    );
}
