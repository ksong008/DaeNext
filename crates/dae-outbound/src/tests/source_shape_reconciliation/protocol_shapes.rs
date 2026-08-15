use super::*;

#[test]
fn protocol_specific_h2_and_meek_rows_reject_their_neighbours() {
    let vless_h2 = standalone(
        MaterializedProtocol::VlessStandard,
        TEST_STANDARD_TLS_VARIANT,
        MaterializedWrapper::H2,
        MaterializedUdp::Vless(MaterializedStreamPacketTransport::H2Tls),
    );
    let vmess_h2 = standalone(
        MaterializedProtocol::VmessAead,
        TEST_STANDARD_TLS_VARIANT,
        MaterializedWrapper::H2,
        MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::VmessH2),
    );
    assert!(matches("vless-h2-stream-wrapper", vless_h2));
    assert!(!matches("vmess-h2-stream-wrapper", vless_h2));
    assert!(matches("vmess-h2-stream-wrapper", vmess_h2));
    assert!(!matches("vless-h2-stream-wrapper", vmess_h2));

    let tls_meek = standalone(
        MaterializedProtocol::VlessStandard,
        TEST_STANDARD_TLS_VARIANT,
        MaterializedWrapper::Meek,
        MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::VlessMeek),
    );
    let reality_meek = MaterializedSourceShape {
        security: MaterializedSecurity::RealityBoring,
        ..tls_meek
    };
    assert!(matches("vless-meek-tls-stream-wrapper", tls_meek));
    assert!(!matches("vless-meek-reality-stream-wrapper", tls_meek));
    assert!(matches("vless-meek-reality-stream-wrapper", reality_meek));
    assert!(!matches("vless-meek-tls-stream-wrapper", reality_meek));
}

#[test]
fn quic_qualifiers_isolate_port_hopping_and_verification() {
    let ordinary_hy2 = MaterializedSourceShape {
        quic_verification: MaterializedQuicVerification::WebPki,
        port_hopping: MaterializedPortHopping::Disabled,
        ..standalone(
            MaterializedProtocol::Hysteria2,
            TEST_QUIC_TLS_VARIANT,
            MaterializedWrapper::QuicStream,
            MaterializedUdp::Hysteria2,
        )
    };
    let port_hopping = MaterializedSourceShape {
        port_hopping: MaterializedPortHopping::Enabled,
        ..ordinary_hy2
    };
    assert!(matches("baseline-quic-auth-endpoint", ordinary_hy2));
    assert!(!matches("quic-port-hopping-surface", ordinary_hy2));
    assert!(matches("quic-port-hopping-surface", port_hopping));
    assert!(!matches("baseline-quic-auth-endpoint", port_hopping));

    let verified_tuic = MaterializedSourceShape {
        quic_verification: MaterializedQuicVerification::WebPki,
        port_hopping: MaterializedPortHopping::NotApplicable,
        ..standalone(
            MaterializedProtocol::Tuic,
            TEST_QUIC_TLS_VARIANT,
            MaterializedWrapper::QuicStream,
            MaterializedUdp::Tuic,
        )
    };
    let insecure_tuic = MaterializedSourceShape {
        quic_verification: MaterializedQuicVerification::Insecure,
        ..verified_tuic
    };
    assert!(matches("verified-quic-security-underlay", verified_tuic));
    assert!(!matches("verified-quic-security-underlay", insecure_tuic));
}

#[test]
fn source_provenance_and_trojan_inner_shape_do_not_alias() {
    let canonical_vmess = standalone(
        MaterializedProtocol::VmessAead,
        TEST_NO_SECURITY_VARIANT,
        MaterializedWrapper::None,
        MaterializedUdp::Vmess(MaterializedStreamPacketTransport::PlainTcp),
    );
    let legacy_vmess = MaterializedSourceShape {
        source_import: MaterializedSourceImport::LegacyVmess,
        ..canonical_vmess
    };
    assert!(matches("baseline-aead-framed-endpoint", canonical_vmess));
    assert!(!matches("baseline-aead-framed-endpoint", legacy_vmess));
    assert!(
        !source_shape_reconciliation("legacy-layer-shape")
            .unwrap()
            .matches(legacy_vmess)
    );

    let trojan_inner = standalone(
        MaterializedProtocol::TrojanInnerShadowsocks,
        TEST_STANDARD_TLS_VARIANT,
        MaterializedWrapper::WebSocket,
        MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::TrojanInnerShadowsocks),
    );
    let ordinary_trojan = MaterializedSourceShape {
        protocol: MaterializedProtocol::Trojan,
        udp: MaterializedUdp::Trojan(MaterializedStreamPacketTransport::WebSocketTls),
        ..trojan_inner
    };
    assert!(matches("inner-encryption-stream-wrapper", trojan_inner));
    assert!(!matches("inner-encryption-stream-wrapper", ordinary_trojan));
}

#[test]
fn passthrough_request_cannot_alias_an_ordinary_packet_shape() {
    let ordinary = standalone(
        MaterializedProtocol::ShadowsocksAead,
        TEST_AEAD_VARIANT,
        MaterializedWrapper::None,
        MaterializedUdp::ShadowsocksAead,
    );
    let requested = MaterializedSourceShape {
        passthrough_udp: MaterializedPassthroughUdp::Requested,
        ..ordinary
    };
    assert!(matches("baseline-aead-cipher-endpoint", ordinary));
    assert!(!matches("baseline-aead-cipher-endpoint", requested));
    assert!(
        !source_shape_reconciliation("passthrough-udp-transport")
            .unwrap()
            .matches(requested)
    );
}

#[test]
fn unrecognized_source_import_cannot_match_a_production_selector() {
    let shape = MaterializedSourceShape {
        source_import: MaterializedSourceImport::Unrecognized,
        ..standalone(
            MaterializedProtocol::VmessAead,
            TEST_NO_SECURITY_VARIANT,
            MaterializedWrapper::None,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::PlainTcp),
        )
    };

    assert!(!matches("baseline-aead-framed-endpoint", shape));
}
