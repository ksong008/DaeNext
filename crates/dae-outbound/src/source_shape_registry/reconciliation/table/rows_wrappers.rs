use super::constructors::*;
use super::selector_sets::*;
use super::*;

pub(super) const STREAM_WRAPPER_WEBSOCKET: SourceShapeReconciliation = production(
    "stream-wrapper-websocket",
    &[
        standalone(
            MaterializedProtocol::VlessStandard,
            FULL_STREAM_TLS_AND_REALITY_VARIANTS,
            MaterializedWrapper::WebSocket,
            MaterializedUdp::Vless(MaterializedStreamPacketTransport::WebSocketTls),
        ),
        standalone(
            MaterializedProtocol::Trojan,
            STREAM_TLS_WITHOUT_FINGERPRINT_VARIANTS,
            MaterializedWrapper::WebSocket,
            MaterializedUdp::Trojan(MaterializedStreamPacketTransport::WebSocketTls),
        ),
    ],
);

pub(super) const PLAIN_WEBSOCKET_FRAMED_ENDPOINT: SourceShapeReconciliation = production(
    "plain-websocket-framed-endpoint",
    &[standalone(
        MaterializedProtocol::VmessAead,
        NO_SECURITY_VARIANTS,
        MaterializedWrapper::WebSocket,
        MaterializedUdp::Vmess(MaterializedStreamPacketTransport::WebSocketPlain),
    )],
);

pub(super) const STREAM_WRAPPER_GRPC: SourceShapeReconciliation = production(
    "stream-wrapper-grpc",
    &[
        standalone(
            MaterializedProtocol::VlessStandard,
            FULL_STREAM_TLS_AND_REALITY_VARIANTS,
            MaterializedWrapper::Grpc,
            MaterializedUdp::Vless(MaterializedStreamPacketTransport::GrpcTls),
        ),
        standalone(
            MaterializedProtocol::VmessAead,
            FULL_STREAM_TLS_VARIANTS,
            MaterializedWrapper::Grpc,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::GrpcTls),
        ),
        standalone(
            MaterializedProtocol::Trojan,
            STREAM_TLS_WITHOUT_FINGERPRINT_VARIANTS,
            MaterializedWrapper::Grpc,
            MaterializedUdp::Trojan(MaterializedStreamPacketTransport::GrpcTls),
        ),
    ],
);

pub(super) const STREAM_WRAPPER_HTTPUPGRADE: SourceShapeReconciliation = production(
    "stream-wrapper-httpupgrade",
    &[
        standalone(
            MaterializedProtocol::VlessStandard,
            FULL_STREAM_TLS_AND_REALITY_VARIANTS,
            MaterializedWrapper::HttpUpgrade,
            MaterializedUdp::Vless(MaterializedStreamPacketTransport::HttpUpgradeTls),
        ),
        standalone(
            MaterializedProtocol::Trojan,
            STREAM_TLS_WITHOUT_FINGERPRINT_VARIANTS,
            MaterializedWrapper::HttpUpgrade,
            MaterializedUdp::Trojan(MaterializedStreamPacketTransport::HttpUpgradeTls),
        ),
    ],
);

pub(super) const PLAIN_HTTPUPGRADE_FRAMED_ENDPOINT: SourceShapeReconciliation = production(
    "plain-httpupgrade-framed-endpoint",
    &[standalone(
        MaterializedProtocol::VmessAead,
        NO_SECURITY_VARIANTS,
        MaterializedWrapper::HttpUpgrade,
        MaterializedUdp::Vmess(MaterializedStreamPacketTransport::HttpUpgradePlain),
    )],
);

pub(super) const STREAM_WRAPPER_MEEK: SourceShapeReconciliation = aggregate(
    "stream-wrapper-meek",
    &[
        aggregate_component("vless-meek-tls-stream-wrapper", SourceShapeProjection::All),
        aggregate_component(
            "vless-meek-reality-stream-wrapper",
            SourceShapeProjection::All,
        ),
    ],
);

pub(super) const VLESS_MEEK_TLS_STREAM_WRAPPER: SourceShapeReconciliation = production(
    "vless-meek-tls-stream-wrapper",
    &[standalone(
        MaterializedProtocol::VlessStandard,
        FULL_STREAM_TLS_VARIANTS,
        MaterializedWrapper::Meek,
        MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::VlessMeek),
    )],
);

pub(super) const VLESS_MEEK_REALITY_STREAM_WRAPPER: SourceShapeReconciliation = production(
    "vless-meek-reality-stream-wrapper",
    &[standalone(
        MaterializedProtocol::VlessStandard,
        REALITY_TLS_VARIANTS,
        MaterializedWrapper::Meek,
        MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::VlessMeek),
    )],
);

pub(super) const VLESS_H2_STREAM_WRAPPER: SourceShapeReconciliation = production(
    "vless-h2-stream-wrapper",
    &[standalone(
        MaterializedProtocol::VlessStandard,
        FULL_STREAM_TLS_VARIANTS,
        MaterializedWrapper::H2,
        MaterializedUdp::Vless(MaterializedStreamPacketTransport::H2Tls),
    )],
);

pub(super) const VMESS_H2_STREAM_WRAPPER: SourceShapeReconciliation = production(
    "vmess-h2-stream-wrapper",
    &[standalone(
        MaterializedProtocol::VmessAead,
        FULL_STREAM_TLS_VARIANTS,
        MaterializedWrapper::H2,
        MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::VmessH2),
    )],
);

pub(super) const XHTTP_H1_WRAPPER: SourceShapeReconciliation = production(
    "xhttp-h1-wrapper",
    &[xhttp(
        FULL_STREAM_TLS_VARIANTS,
        MaterializedWrapper::XhttpH1,
        MaterializedUdp::Vless(MaterializedStreamPacketTransport::XhttpH1),
        MaterializedXhttpSettings::Default,
    )],
);

pub(super) const STREAM_WRAPPER_XHTTP: SourceShapeReconciliation = production(
    "stream-wrapper-xhttp",
    &[xhttp(
        FULL_STREAM_TLS_AND_REALITY_VARIANTS,
        MaterializedWrapper::XhttpH2,
        MaterializedUdp::Vless(MaterializedStreamPacketTransport::XhttpH2),
        MaterializedXhttpSettings::Default,
    )],
);

pub(super) const NESTED_CHAIN_SHAPE: SourceShapeReconciliation = production(
    "nested-chain-shape",
    &[
        chained_policy_closed(
            MaterializedProtocol::Socks5,
            NO_SECURITY_VARIANTS,
            MaterializedWrapper::None,
            MaterializedUdp::Socks5Associate,
        ),
        chained_policy_closed(
            MaterializedProtocol::HttpProxy,
            NO_SECURITY_VARIANTS,
            MaterializedWrapper::None,
            MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::HttpConnect),
        ),
        chained_policy_closed(
            MaterializedProtocol::HttpProxy,
            NO_SECURITY_VARIANTS,
            MaterializedWrapper::HttpTransport,
            MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::HttpConnect),
        ),
        chained_policy_closed(
            MaterializedProtocol::ShadowsocksAead,
            AEAD_VARIANTS,
            MaterializedWrapper::None,
            MaterializedUdp::ShadowsocksAead,
        ),
        chained_policy_closed(
            MaterializedProtocol::Shadowsocks2022,
            AEAD_2022_VARIANTS,
            MaterializedWrapper::None,
            MaterializedUdp::Shadowsocks2022,
        ),
        chained_policy_closed(
            MaterializedProtocol::ShadowsocksSimpleObfsHttp,
            AEAD_VARIANTS,
            MaterializedWrapper::SimpleObfsHttp,
            MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::PluginWrapper),
        ),
        chained_policy_closed(
            MaterializedProtocol::ShadowsocksSimpleObfsTls,
            AEAD_VARIANTS,
            MaterializedWrapper::SimpleObfsTls,
            MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::PluginWrapper),
        ),
        chained_policy_closed(
            MaterializedProtocol::ShadowsocksV2rayPluginTlsWebSocket,
            SHADOWSOCKS_V2RAY_PLUGIN_TLS_VARIANTS,
            MaterializedWrapper::V2rayPluginTlsWebSocket,
            MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::PluginWrapper),
        ),
        chained_policy_closed(
            MaterializedProtocol::Shadowsocks2022SimpleObfsHttp,
            AEAD_2022_VARIANTS,
            MaterializedWrapper::SimpleObfsHttp,
            MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::PluginWrapper),
        ),
        chained_policy_closed(
            MaterializedProtocol::ShadowsocksRHttpSimple,
            LEGACY_CIPHER_VARIANTS,
            MaterializedWrapper::LegacyObfs,
            MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::ShadowsocksR),
        ),
        chained_parent_stream(
            MaterializedProtocol::VmessAead,
            NO_SECURITY_VARIANTS,
            MaterializedWrapper::None,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::PlainTcp),
        ),
        chained_parent_stream(
            MaterializedProtocol::VmessAead,
            NO_SECURITY_VARIANTS,
            MaterializedWrapper::WebSocket,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::WebSocketPlain),
        ),
        chained_parent_stream(
            MaterializedProtocol::VmessAead,
            NO_SECURITY_VARIANTS,
            MaterializedWrapper::HttpUpgrade,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::HttpUpgradePlain),
        ),
    ],
);

pub(super) const PLUGIN_WRAPPER_LAYER: SourceShapeReconciliation = production(
    "plugin-wrapper-layer",
    &[standalone(
        MaterializedProtocol::ShadowsocksSimpleObfsHttp,
        AEAD_VARIANTS,
        MaterializedWrapper::SimpleObfsHttp,
        MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::PluginWrapper),
    )],
);

pub(super) const QUIC_OPTION_SURFACE: SourceShapeReconciliation = aggregate(
    "quic-option-surface",
    &[
        aggregate_component("baseline-quic-auth-endpoint", SourceShapeProjection::All),
        aggregate_component("baseline-quic-uuid-endpoint", SourceShapeProjection::All),
        aggregate_component(
            "baseline-quic-password-endpoint",
            SourceShapeProjection::All,
        ),
        aggregate_component("quic-port-hopping-surface", SourceShapeProjection::All),
        aggregate_component(
            "verified-quic-security-underlay",
            SourceShapeProjection::All,
        ),
    ],
);
