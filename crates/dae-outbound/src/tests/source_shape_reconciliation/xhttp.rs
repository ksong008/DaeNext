use super::*;

#[test]
fn versions_are_correlated_and_extended_settings_remain_aggregate() {
    let h1 = MaterializedSourceShape {
        xhttp_mode: MaterializedXhttpMode::PacketUp,
        xhttp_settings: MaterializedXhttpSettings::Default,
        ..standalone(
            MaterializedProtocol::VlessStandard,
            TEST_STANDARD_TLS_VARIANT,
            MaterializedWrapper::XhttpH1,
            MaterializedUdp::Vless(MaterializedStreamPacketTransport::XhttpH1),
        )
    };
    let h2 = MaterializedSourceShape {
        wrapper: MaterializedWrapper::XhttpH2,
        udp: MaterializedUdp::Vless(MaterializedStreamPacketTransport::XhttpH2),
        ..h1
    };
    let h3 = MaterializedSourceShape {
        security: MaterializedSecurity::QuicTls,
        tls_features: MaterializedTlsFeatures::NONE,
        wrapper: MaterializedWrapper::XhttpH3,
        udp: MaterializedUdp::Vless(MaterializedStreamPacketTransport::XhttpH3),
        quic_verification: MaterializedQuicVerification::WebPki,
        ..h1
    };
    assert!(matches("xhttp-h1-wrapper", h1));
    assert!(!matches("stream-wrapper-xhttp", h1));
    assert!(matches("stream-wrapper-xhttp", h2));
    assert!(!matches("xhttp-h3-wrapper", h2));
    assert!(matches("xhttp-h3-wrapper", h3));
    let h3_row = source_shape_registry_rows()
        .iter()
        .find(|row| row.shape_id == "xhttp-h3-wrapper")
        .unwrap();
    assert_eq!(h3_row.security_underlay, "quic-tls");
    let h3_security = h3_row
        .typed_capability_contract()
        .unwrap()
        .security_underlay;
    assert!(h3_security.supports_allow_insecure());
    assert!(!h3_security.supports_fingerprint_utls());
    assert!(!h3_security.supports_tls_fragment());
    assert!(matches(
        "xhttp-h3-wrapper",
        MaterializedSourceShape {
            quic_verification: MaterializedQuicVerification::Insecure,
            ..h3
        }
    ));

    for (security, tls_features, quic_verification) in [
        (
            MaterializedSecurity::StandardTls,
            MaterializedTlsFeatures::NONE,
            MaterializedQuicVerification::WebPki,
        ),
        (
            MaterializedSecurity::QuicTls,
            MaterializedTlsFeatures::FRAGMENT,
            MaterializedQuicVerification::WebPki,
        ),
        (
            MaterializedSecurity::QuicTls,
            MaterializedTlsFeatures::FINGERPRINT,
            MaterializedQuicVerification::WebPki,
        ),
        (
            MaterializedSecurity::QuicTls,
            MaterializedTlsFeatures::NONE,
            MaterializedQuicVerification::NotApplicable,
        ),
    ] {
        let unsupported_h3_security = MaterializedSourceShape {
            security,
            tls_features,
            quic_verification,
            ..h3
        };
        assert!(!matches("xhttp-h3-wrapper", unsupported_h3_security));
        assert!(!matches(
            "xhttp-extended-settings-wrapper",
            MaterializedSourceShape {
                xhttp_settings: MaterializedXhttpSettings::Extended,
                ..unsupported_h3_security
            }
        ));
    }

    let extended = MaterializedSourceShape {
        xhttp_settings: MaterializedXhttpSettings::Extended,
        ..h2
    };
    let extended_contract = source_shape_reconciliation("xhttp-extended-settings-wrapper").unwrap();
    let extended_row = source_shape_registry_rows()
        .iter()
        .find(|row| row.shape_id == "xhttp-extended-settings-wrapper")
        .unwrap();
    assert_eq!(extended_row.resident_status, "blocked");
    assert_eq!(
        extended_row.blocker_id,
        Some("extended-xhttp-shape-not-exactly-classified")
    );
    assert_eq!(extended_row.packet_semantics, "extended-xhttp");
    assert_eq!(
        extended_contract.kind,
        SourceShapeReconciliationKind::AggregateCapability
    );
    assert!(extended_contract.classifies(extended));
    assert!(!extended_contract.matches(extended));
    assert!(!matches("stream-wrapper-xhttp", extended));
}
