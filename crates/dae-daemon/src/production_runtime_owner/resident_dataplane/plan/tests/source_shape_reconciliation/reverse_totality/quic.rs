use super::*;
use dae_outbound::{
    MaterializedPortHopping, MaterializedQuicVerification, MaterializedSecurity,
    MaterializedTlsFeatures, MaterializedTlsVariant,
};

#[test]
fn hysteria2_verification_and_hopping_cross_product_has_exact_rows() {
    for hopping in [false, true] {
        for (insecure, pin, verification) in verification_cases() {
            let source = hysteria2_source(hopping, insecure, pin);
            let expected_id = if hopping {
                "quic-port-hopping-surface"
            } else {
                "baseline-quic-auth-endpoint"
            };
            let shape = assert_exact_source(&source, &fixture_config(), &[expected_id]);
            assert_quic_tls(shape);
            assert_eq!(shape.quic_verification, verification);
            assert_eq!(
                shape.port_hopping,
                if hopping {
                    MaterializedPortHopping::Enabled
                } else {
                    MaterializedPortHopping::Disabled
                }
            );
        }
    }
}

#[test]
fn juicity_verification_cross_product_has_one_exact_row() {
    for (insecure, pin, verification) in verification_cases() {
        let source = juicity_source(insecure, pin);
        let shape = assert_exact_source(
            &source,
            &fixture_config(),
            &["baseline-quic-password-endpoint"],
        );
        assert_quic_tls(shape);
        assert_eq!(shape.quic_verification, verification);
        assert_eq!(shape.port_hopping, MaterializedPortHopping::NotApplicable);
    }
}

#[test]
fn connect_udp_h2_and_h3_sources_remain_policy_closed() {
    let config = fixture_config();
    for transport in ["h2", "h3"] {
        for allow_insecure in [false, true] {
            let source = connect_udp_source(transport, allow_insecure);
            let expected_id = if transport == "h2" {
                "connect-udp-h2-endpoint"
            } else {
                "connect-udp-h3-endpoint"
            };
            let error = build_resident_proxy_plan_for_node(
                &config,
                "proxy".to_owned(),
                "connect-udp-policy".to_owned(),
                source,
            )
            .expect_err("removed CONNECT-UDP source must remain fail-closed");
            assert!(error.contains("unsupported masque node"), "{error}");
            assert_eq!(
                source_shape_reconciliation(expected_id).unwrap().kind,
                SourceShapeReconciliationKind::SourceRejected,
            );
        }
    }
}

fn verification_cases() -> [(bool, Option<&'static str>, MaterializedQuicVerification); 4] {
    [
        (false, None, MaterializedQuicVerification::WebPki),
        (true, None, MaterializedQuicVerification::Insecure),
        (
            false,
            Some("pin"),
            MaterializedQuicVerification::WebPkiAndPin,
        ),
        (true, Some("pin"), MaterializedQuicVerification::PinOnly),
    ]
}

fn hysteria2_source(hopping: bool, insecure: bool, pin: Option<&str>) -> String {
    let server = if hopping {
        fixture_hop_server(
            fixture_port(5),
            &format!(",{}-{}", fixture_port(6), fixture_port(7)),
        )
    } else {
        format!(
            "{}:{}",
            fixture_host(FixtureEndpoint::Primary),
            fixture_port(5)
        )
    };
    Hysteria2Link {
        name: String::new(),
        user: fixture_user(),
        password: String::new(),
        server,
        insecure,
        sni: fixture_host(FixtureEndpoint::Authority),
        pin_sha256: pin.map_or_else(String::new, |_| fixture_pin_sha256()),
        obfs: String::new(),
        obfs_password: String::new(),
        max_tx: 0,
        max_rx: 0,
    }
    .export_url()
}

fn juicity_source(insecure: bool, pin: Option<&str>) -> String {
    JuicityLink {
        name: String::new(),
        user: fixture_client_id(),
        password: fixture_secret(),
        server: fixture_host(FixtureEndpoint::Primary),
        port: fixture_port(7),
        sni: fixture_host(FixtureEndpoint::Authority),
        allow_insecure: insecure,
        congestion_control: String::new(),
        pinned_certchain_sha256: pin.map_or_else(String::new, |_| fixture_pin_sha256()),
        protocol: "juicity".to_owned(),
    }
    .export_url()
}

fn connect_udp_source(transport: &str, allow_insecure: bool) -> String {
    let insecure = if allow_insecure {
        "&allowInsecure=true"
    } else {
        ""
    };
    format!(
        "masque://identity:credential@{}:{}?transport={transport}&auth=basic&template=%2F.well-known%2Fmasque%2Fudp%2F%7Btarget_host%7D%2F%7Btarget_port%7D%2F&sni={}{}",
        fixture_host(FixtureEndpoint::Primary),
        fixture_port(8),
        fixture_host(FixtureEndpoint::Authority),
        insecure,
    )
}

fn assert_quic_tls(shape: MaterializedSourceShape) {
    assert_eq!(
        shape.tls_variant(),
        MaterializedTlsVariant::new(MaterializedSecurity::QuicTls, MaterializedTlsFeatures::NONE)
    );
}
