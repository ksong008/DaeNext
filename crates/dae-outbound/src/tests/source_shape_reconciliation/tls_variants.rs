use super::*;

const fn tls_variant(
    security: MaterializedSecurity,
    features: MaterializedTlsFeatures,
) -> MaterializedTlsVariant {
    MaterializedTlsVariant::new(security, features)
}

const FULL_STREAM_TLS_VARIANTS: &[MaterializedTlsVariant] = &[
    tls_variant(
        MaterializedSecurity::StandardTls,
        MaterializedTlsFeatures::NONE,
    ),
    tls_variant(
        MaterializedSecurity::InsecureTls,
        MaterializedTlsFeatures::ALLOW_INSECURE,
    ),
    tls_variant(
        MaterializedSecurity::InsecureTls,
        MaterializedTlsFeatures::ALLOW_INSECURE_FRAGMENT,
    ),
    tls_variant(
        MaterializedSecurity::FragmentedTls,
        MaterializedTlsFeatures::FRAGMENT,
    ),
    tls_variant(
        MaterializedSecurity::FingerprintAwareTls,
        MaterializedTlsFeatures::FINGERPRINT,
    ),
    tls_variant(
        MaterializedSecurity::FingerprintAwareTls,
        MaterializedTlsFeatures::ALLOW_INSECURE_FINGERPRINT,
    ),
    tls_variant(
        MaterializedSecurity::FingerprintAwareTls,
        MaterializedTlsFeatures::FRAGMENT_FINGERPRINT,
    ),
    tls_variant(
        MaterializedSecurity::FingerprintAwareTls,
        MaterializedTlsFeatures::ALLOW_INSECURE_FRAGMENT_FINGERPRINT,
    ),
];

const STREAM_TLS_WITHOUT_FINGERPRINT_VARIANTS: &[MaterializedTlsVariant] = &[
    FULL_STREAM_TLS_VARIANTS[0],
    FULL_STREAM_TLS_VARIANTS[1],
    FULL_STREAM_TLS_VARIANTS[2],
    FULL_STREAM_TLS_VARIANTS[3],
];

const REALITY_TLS_VARIANTS: &[MaterializedTlsVariant] = &[
    tls_variant(
        MaterializedSecurity::RealityRustls,
        MaterializedTlsFeatures::NONE,
    ),
    tls_variant(
        MaterializedSecurity::RealityFingerprint,
        MaterializedTlsFeatures::FINGERPRINT,
    ),
];

const QUIC_TLS_VARIANT: MaterializedTlsVariant =
    tls_variant(MaterializedSecurity::QuicTls, MaterializedTlsFeatures::NONE);

fn selector(shape_id: &str, protocol: MaterializedProtocol) -> SourceShapeSelector {
    source_shape_reconciliation(shape_id)
        .unwrap_or_else(|| panic!("missing reconciliation for {shape_id}"))
        .selectors
        .iter()
        .copied()
        .find(|selector| selector.protocol == protocol)
        .unwrap_or_else(|| panic!("missing {protocol:?} selector for {shape_id}"))
}

fn assert_exact_variants(
    shape_id: &str,
    protocol: MaterializedProtocol,
    expected: &[MaterializedTlsVariant],
) {
    let actual = selector(shape_id, protocol).tls_variants;
    assert_eq!(actual.len(), expected.len(), "{shape_id}");
    for variant in expected {
        assert!(actual.contains(variant), "{shape_id}: {variant:?}");
    }
}

#[test]
fn protocol_selectors_preserve_exact_tls_responsibilities() {
    assert_exact_variants(
        "baseline-tls-vision-endpoint",
        MaterializedProtocol::VlessVision,
        FULL_STREAM_TLS_VARIANTS,
    );
    assert_exact_variants(
        "stream-wrapper-websocket",
        MaterializedProtocol::Trojan,
        STREAM_TLS_WITHOUT_FINGERPRINT_VARIANTS,
    );
    assert_exact_variants(
        "connect-udp-h2-endpoint",
        MaterializedProtocol::ConnectUdpH2,
        &FULL_STREAM_TLS_VARIANTS[..2],
    );
    assert_exact_variants(
        "vless-meek-reality-stream-wrapper",
        MaterializedProtocol::VlessStandard,
        REALITY_TLS_VARIANTS,
    );
    assert_exact_variants(
        "connect-udp-h3-endpoint",
        MaterializedProtocol::ConnectUdpH3,
        &[QUIC_TLS_VARIANT],
    );
    assert_exact_variants(
        "xhttp-h3-wrapper",
        MaterializedProtocol::VlessStandard,
        &[QUIC_TLS_VARIANT],
    );
    assert_exact_variants(
        "baseline-aead-cipher-endpoint",
        MaterializedProtocol::ShadowsocksAead,
        &[tls_variant(
            MaterializedSecurity::Aead,
            MaterializedTlsFeatures::NONE,
        )],
    );
    assert_exact_variants(
        "tls-websocket-plugin-wrapper",
        MaterializedProtocol::ShadowsocksV2rayPluginTlsWebSocket,
        &[FULL_STREAM_TLS_VARIANTS[0], FULL_STREAM_TLS_VARIANTS[3]],
    );
}

#[test]
fn connect_udp_h2_rejects_fragmented_insecure_tls_variant() {
    let standard = standalone(
        MaterializedProtocol::ConnectUdpH2,
        TEST_STANDARD_TLS_VARIANT,
        MaterializedWrapper::ConnectUdpH2,
        MaterializedUdp::ConnectUdpH2,
    );
    let insecure = MaterializedSourceShape {
        security: MaterializedSecurity::InsecureTls,
        tls_features: MaterializedTlsFeatures::ALLOW_INSECURE,
        ..standard
    };
    let insecure_fragmented = MaterializedSourceShape {
        tls_features: MaterializedTlsFeatures::ALLOW_INSECURE_FRAGMENT,
        ..insecure
    };

    assert!(matches("connect-udp-h2-endpoint", standard));
    assert!(matches("connect-udp-h2-endpoint", insecure));
    assert!(!matches("connect-udp-h2-endpoint", insecure_fragmented));
}

#[test]
fn protocol_selectors_contain_only_builder_reachable_tls_variants() {
    let mut builder_reachable = vec![
        tls_variant(MaterializedSecurity::None, MaterializedTlsFeatures::NONE),
        tls_variant(MaterializedSecurity::Aead, MaterializedTlsFeatures::NONE),
        tls_variant(
            MaterializedSecurity::Aead2022,
            MaterializedTlsFeatures::NONE,
        ),
        tls_variant(
            MaterializedSecurity::LegacyCipher,
            MaterializedTlsFeatures::NONE,
        ),
        QUIC_TLS_VARIANT,
    ];
    builder_reachable.extend_from_slice(FULL_STREAM_TLS_VARIANTS);
    builder_reachable.extend_from_slice(REALITY_TLS_VARIANTS);

    for reconciliation in source_shape_reconciliations() {
        for selector in reconciliation.selectors {
            for variant in selector.tls_variants {
                assert!(
                    builder_reachable.contains(variant),
                    "{} contains impossible TLS variant {variant:?}",
                    reconciliation.shape_id
                );
            }
        }
    }

    let impossible = tls_variant(
        MaterializedSecurity::StandardTls,
        MaterializedTlsFeatures::FRAGMENT,
    );
    assert!(source_shape_reconciliations().iter().all(|reconciliation| {
        reconciliation
            .selectors
            .iter()
            .all(|selector| !selector.tls_variants.contains(&impossible))
    }));
}
