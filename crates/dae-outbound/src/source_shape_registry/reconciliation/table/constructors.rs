use super::selector_sets::*;
use super::*;

pub(super) const fn standalone(
    protocol: MaterializedProtocol,
    tls_variants: &'static [MaterializedTlsVariant],
    wrapper: MaterializedWrapper,
    udp: MaterializedUdp,
) -> SourceShapeSelector {
    SourceShapeSelector {
        protocol,
        tls_variants,
        wrapper,
        udp,
        chain: MaterializedChain::Standalone,
        chain_udp: MaterializedChainUdp::NotChained,
        xhttp_modes: NOT_XHTTP,
        xhttp_settings: MaterializedXhttpSettings::NotApplicable,
        quic_verification: NOT_QUIC_VERIFICATION,
        port_hopping: MaterializedPortHopping::NotApplicable,
        source_import: MaterializedSourceImport::Canonical,
        passthrough_udp: MaterializedPassthroughUdp::NotRequested,
    }
}

const fn chained(
    protocol: MaterializedProtocol,
    tls_variants: &'static [MaterializedTlsVariant],
    wrapper: MaterializedWrapper,
    udp: MaterializedUdp,
    chain_udp: MaterializedChainUdp,
) -> SourceShapeSelector {
    SourceShapeSelector {
        chain: MaterializedChain::ParentConnect,
        chain_udp,
        ..standalone(protocol, tls_variants, wrapper, udp)
    }
}

pub(super) const fn chained_parent_stream(
    protocol: MaterializedProtocol,
    tls_variants: &'static [MaterializedTlsVariant],
    wrapper: MaterializedWrapper,
    udp: MaterializedUdp,
) -> SourceShapeSelector {
    chained(
        protocol,
        tls_variants,
        wrapper,
        udp,
        MaterializedChainUdp::ParentStream,
    )
}

pub(super) const fn chained_policy_closed(
    protocol: MaterializedProtocol,
    tls_variants: &'static [MaterializedTlsVariant],
    wrapper: MaterializedWrapper,
    udp: MaterializedUdp,
) -> SourceShapeSelector {
    chained(
        protocol,
        tls_variants,
        wrapper,
        udp,
        MaterializedChainUdp::PolicyClosed,
    )
}

pub(super) const fn quic(
    protocol: MaterializedProtocol,
    udp: MaterializedUdp,
    verification: &'static [MaterializedQuicVerification],
    port_hopping: MaterializedPortHopping,
) -> SourceShapeSelector {
    SourceShapeSelector {
        protocol,
        tls_variants: QUIC_TLS_VARIANTS,
        wrapper: MaterializedWrapper::QuicStream,
        udp,
        chain: MaterializedChain::Standalone,
        chain_udp: MaterializedChainUdp::NotChained,
        xhttp_modes: NOT_XHTTP,
        xhttp_settings: MaterializedXhttpSettings::NotApplicable,
        quic_verification: verification,
        port_hopping,
        source_import: MaterializedSourceImport::Canonical,
        passthrough_udp: MaterializedPassthroughUdp::NotRequested,
    }
}

pub(super) const fn xhttp(
    tls_variants: &'static [MaterializedTlsVariant],
    wrapper: MaterializedWrapper,
    udp: MaterializedUdp,
    settings: MaterializedXhttpSettings,
) -> SourceShapeSelector {
    SourceShapeSelector {
        protocol: MaterializedProtocol::VlessStandard,
        tls_variants,
        wrapper,
        udp,
        chain: MaterializedChain::Standalone,
        chain_udp: MaterializedChainUdp::NotChained,
        xhttp_modes: XHTTP_MODES,
        xhttp_settings: settings,
        quic_verification: NOT_QUIC_VERIFICATION,
        port_hopping: MaterializedPortHopping::NotApplicable,
        source_import: MaterializedSourceImport::Canonical,
        passthrough_udp: MaterializedPassthroughUdp::NotRequested,
    }
}

pub(super) const fn xhttp_h3(settings: MaterializedXhttpSettings) -> SourceShapeSelector {
    SourceShapeSelector {
        protocol: MaterializedProtocol::VlessStandard,
        tls_variants: QUIC_TLS_VARIANTS,
        wrapper: MaterializedWrapper::XhttpH3,
        udp: MaterializedUdp::Vless(MaterializedStreamPacketTransport::XhttpH3),
        chain: MaterializedChain::Standalone,
        chain_udp: MaterializedChainUdp::NotChained,
        xhttp_modes: XHTTP_MODES,
        xhttp_settings: settings,
        quic_verification: &[
            MaterializedQuicVerification::WebPki,
            MaterializedQuicVerification::Insecure,
        ],
        port_hopping: MaterializedPortHopping::NotApplicable,
        source_import: MaterializedSourceImport::Canonical,
        passthrough_udp: MaterializedPassthroughUdp::NotRequested,
    }
}

pub(super) const fn with_source_import(
    selector: SourceShapeSelector,
    source_import: MaterializedSourceImport,
) -> SourceShapeSelector {
    SourceShapeSelector {
        source_import,
        ..selector
    }
}

pub(super) const fn production(
    shape_id: &'static str,
    selectors: &'static [SourceShapeSelector],
) -> SourceShapeReconciliation {
    SourceShapeReconciliation {
        shape_id,
        kind: SourceShapeReconciliationKind::ProductionWitness,
        selectors,
        classification_selectors: &[],
        aggregate_components: &[],
    }
}

pub(super) const fn aggregate(
    shape_id: &'static str,
    aggregate_components: &'static [SourceShapeAggregateComponent],
) -> SourceShapeReconciliation {
    SourceShapeReconciliation {
        shape_id,
        kind: SourceShapeReconciliationKind::AggregateCapability,
        selectors: &[],
        classification_selectors: &[],
        aggregate_components,
    }
}

pub(super) const fn classified_aggregate(
    shape_id: &'static str,
    classification_selectors: &'static [SourceShapeSelector],
) -> SourceShapeReconciliation {
    SourceShapeReconciliation {
        shape_id,
        kind: SourceShapeReconciliationKind::AggregateCapability,
        selectors: &[],
        classification_selectors,
        aggregate_components: &[],
    }
}

pub(super) const fn deferred(shape_id: &'static str) -> SourceShapeReconciliation {
    SourceShapeReconciliation {
        shape_id,
        kind: SourceShapeReconciliationKind::DeferredCapability,
        selectors: &[],
        classification_selectors: &[],
        aggregate_components: &[],
    }
}

pub(super) const fn classified_deferred(
    shape_id: &'static str,
    classification_selectors: &'static [SourceShapeSelector],
) -> SourceShapeReconciliation {
    SourceShapeReconciliation {
        shape_id,
        kind: SourceShapeReconciliationKind::DeferredCapability,
        selectors: &[],
        classification_selectors,
        aggregate_components: &[],
    }
}

pub(super) const fn rejected(shape_id: &'static str) -> SourceShapeReconciliation {
    SourceShapeReconciliation {
        shape_id,
        kind: SourceShapeReconciliationKind::SourceRejected,
        selectors: &[],
        classification_selectors: &[],
        aggregate_components: &[],
    }
}

pub(super) const fn aggregate_component(
    shape_id: &'static str,
    projection: SourceShapeProjection,
) -> SourceShapeAggregateComponent {
    SourceShapeAggregateComponent::new(shape_id, projection)
}
