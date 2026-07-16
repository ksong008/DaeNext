use super::*;

mod aggregates;
mod chains;
mod protocol_shapes;
mod registry_totality;
mod tls_variants;
mod xhttp;

const TEST_NO_SECURITY_VARIANT: MaterializedTlsVariant =
    MaterializedTlsVariant::new(MaterializedSecurity::None, MaterializedTlsFeatures::NONE);
const TEST_AEAD_VARIANT: MaterializedTlsVariant =
    MaterializedTlsVariant::new(MaterializedSecurity::Aead, MaterializedTlsFeatures::NONE);
const TEST_STANDARD_TLS_VARIANT: MaterializedTlsVariant = MaterializedTlsVariant::new(
    MaterializedSecurity::StandardTls,
    MaterializedTlsFeatures::NONE,
);
const TEST_QUIC_TLS_VARIANT: MaterializedTlsVariant =
    MaterializedTlsVariant::new(MaterializedSecurity::QuicTls, MaterializedTlsFeatures::NONE);

fn standalone(
    protocol: MaterializedProtocol,
    tls_variant: MaterializedTlsVariant,
    wrapper: MaterializedWrapper,
    udp: MaterializedUdp,
) -> MaterializedSourceShape {
    MaterializedSourceShape {
        protocol,
        security: tls_variant.security,
        tls_features: tls_variant.features,
        wrapper,
        udp,
        chain: MaterializedChain::Standalone,
        chain_udp: MaterializedChainUdp::NotChained,
        xhttp_mode: MaterializedXhttpMode::NotApplicable,
        xhttp_settings: MaterializedXhttpSettings::NotApplicable,
        quic_verification: MaterializedQuicVerification::NotApplicable,
        port_hopping: MaterializedPortHopping::NotApplicable,
        source_import: MaterializedSourceImport::Canonical,
        passthrough_udp: MaterializedPassthroughUdp::NotRequested,
    }
}

fn matches(shape_id: &str, shape: MaterializedSourceShape) -> bool {
    source_shape_reconciliation(shape_id)
        .unwrap_or_else(|| panic!("missing reconciliation for {shape_id}"))
        .matches(shape)
}
