use super::constructors::*;
use super::selector_sets::*;
use super::*;

pub(super) const LEGACY_LAYER_SHAPE: SourceShapeReconciliation = classified_deferred(
    "legacy-layer-shape",
    &[
        legacy_vmess(
            NO_SECURITY_VARIANTS,
            MaterializedWrapper::None,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::PlainTcp),
        ),
        legacy_vmess(
            FULL_STREAM_TLS_VARIANTS,
            MaterializedWrapper::None,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::TlsTcp),
        ),
        legacy_vmess(
            NO_SECURITY_VARIANTS,
            MaterializedWrapper::WebSocket,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::WebSocketPlain),
        ),
        legacy_vmess(
            FULL_STREAM_TLS_VARIANTS,
            MaterializedWrapper::WebSocket,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::WebSocketTls),
        ),
        legacy_vmess(
            NO_SECURITY_VARIANTS,
            MaterializedWrapper::HttpUpgrade,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::HttpUpgradePlain),
        ),
        legacy_vmess(
            FULL_STREAM_TLS_VARIANTS,
            MaterializedWrapper::HttpUpgrade,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::HttpUpgradeTls),
        ),
        legacy_vmess(
            FULL_STREAM_TLS_VARIANTS,
            MaterializedWrapper::Grpc,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::GrpcTls),
        ),
        legacy_vmess(
            FULL_STREAM_TLS_VARIANTS,
            MaterializedWrapper::H2,
            MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::VmessH2),
        ),
        chained_legacy_vmess(
            MaterializedWrapper::None,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::PlainTcp),
        ),
        chained_legacy_vmess(
            MaterializedWrapper::WebSocket,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::WebSocketPlain),
        ),
        chained_legacy_vmess(
            MaterializedWrapper::HttpUpgrade,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::HttpUpgradePlain),
        ),
    ],
);

pub(super) const XHTTP_EXTENDED_SETTINGS_WRAPPER: SourceShapeReconciliation = classified_aggregate(
    "xhttp-extended-settings-wrapper",
    &[
        xhttp(
            FULL_STREAM_TLS_VARIANTS,
            MaterializedWrapper::XhttpH1,
            MaterializedUdp::Vless(MaterializedStreamPacketTransport::XhttpH1),
            MaterializedXhttpSettings::Extended,
        ),
        xhttp(
            FULL_STREAM_TLS_AND_REALITY_VARIANTS,
            MaterializedWrapper::XhttpH2,
            MaterializedUdp::Vless(MaterializedStreamPacketTransport::XhttpH2),
            MaterializedXhttpSettings::Extended,
        ),
        xhttp_h3(MaterializedXhttpSettings::Extended),
    ],
);

const fn legacy_vmess(
    tls_variants: &'static [MaterializedTlsVariant],
    wrapper: MaterializedWrapper,
    udp: MaterializedUdp,
) -> SourceShapeSelector {
    with_source_import(
        standalone(MaterializedProtocol::VmessAead, tls_variants, wrapper, udp),
        MaterializedSourceImport::LegacyVmess,
    )
}

const fn chained_legacy_vmess(
    wrapper: MaterializedWrapper,
    udp: MaterializedUdp,
) -> SourceShapeSelector {
    with_source_import(
        chained_parent_stream(
            MaterializedProtocol::VmessAead,
            NO_SECURITY_VARIANTS,
            wrapper,
            udp,
        ),
        MaterializedSourceImport::LegacyVmess,
    )
}
