use super::constructors::*;
use super::selector_sets::*;
use super::*;

pub(super) const SECURE_ENDPOINT_CAPABILITY: SourceShapeReconciliation = production(
    "secure-endpoint-capability",
    &[standalone(
        MaterializedProtocol::HttpProxy,
        STANDARD_OR_FRAGMENTED_TLS_VARIANTS,
        MaterializedWrapper::None,
        MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::HttpConnect),
    )],
);

pub(super) const SECURE_WEBSOCKET_FRAMED_ENDPOINT: SourceShapeReconciliation = production(
    "secure-websocket-framed-endpoint",
    &[standalone(
        MaterializedProtocol::VmessAead,
        FULL_STREAM_TLS_VARIANTS,
        MaterializedWrapper::WebSocket,
        MaterializedUdp::Vmess(MaterializedStreamPacketTransport::WebSocketTls),
    )],
);

pub(super) const SECURE_HTTPUPGRADE_FRAMED_ENDPOINT: SourceShapeReconciliation = production(
    "secure-httpupgrade-framed-endpoint",
    &[standalone(
        MaterializedProtocol::VmessAead,
        FULL_STREAM_TLS_VARIANTS,
        MaterializedWrapper::HttpUpgrade,
        MaterializedUdp::Vmess(MaterializedStreamPacketTransport::HttpUpgradeTls),
    )],
);

pub(super) const REALITY_SECURITY_UNDERLAY: SourceShapeReconciliation = production(
    "reality-security-underlay",
    &[standalone(
        MaterializedProtocol::VlessVision,
        REALITY_TLS_VARIANTS,
        MaterializedWrapper::None,
        MaterializedUdp::VlessVision,
    )],
);

pub(super) const QUIC_PORT_HOPPING_SURFACE: SourceShapeReconciliation = production(
    "quic-port-hopping-surface",
    &[quic(
        MaterializedProtocol::Hysteria2,
        MaterializedUdp::Hysteria2,
        ALL_QUIC_VERIFICATION,
        MaterializedPortHopping::Enabled,
    )],
);

pub(super) const VERIFIED_QUIC_SECURITY_UNDERLAY: SourceShapeReconciliation = production(
    "verified-quic-security-underlay",
    &[quic(
        MaterializedProtocol::Tuic,
        MaterializedUdp::Tuic,
        &[MaterializedQuicVerification::WebPki],
        MaterializedPortHopping::NotApplicable,
    )],
);

pub(super) const INNER_ENCRYPTION_STREAM_WRAPPER: SourceShapeReconciliation = production(
    "inner-encryption-stream-wrapper",
    &[standalone(
        MaterializedProtocol::TrojanInnerShadowsocks,
        STREAM_TLS_WITHOUT_FINGERPRINT_VARIANTS,
        MaterializedWrapper::WebSocket,
        MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::TrojanInnerShadowsocks),
    )],
);

pub(super) const TLS_WEBSOCKET_PLUGIN_WRAPPER: SourceShapeReconciliation = production(
    "tls-websocket-plugin-wrapper",
    &[standalone(
        MaterializedProtocol::ShadowsocksV2rayPluginTlsWebSocket,
        SHADOWSOCKS_V2RAY_PLUGIN_TLS_VARIANTS,
        MaterializedWrapper::V2rayPluginTlsWebSocket,
        MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::PluginWrapper),
    )],
);

pub(super) const OBFS_TLS_PLUGIN_WRAPPER: SourceShapeReconciliation = production(
    "obfs-tls-plugin-wrapper",
    &[standalone(
        MaterializedProtocol::ShadowsocksSimpleObfsTls,
        AEAD_VARIANTS,
        MaterializedWrapper::SimpleObfsTls,
        MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::PluginWrapper),
    )],
);

pub(super) const AEAD_2022_PLUGIN_WRAPPER: SourceShapeReconciliation = production(
    "aead-2022-plugin-wrapper",
    &[standalone(
        MaterializedProtocol::Shadowsocks2022SimpleObfsHttp,
        AEAD_2022_VARIANTS,
        MaterializedWrapper::SimpleObfsHttp,
        MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::PluginWrapper),
    )],
);

pub(super) const PROXY_TRANSPORT_MODE: SourceShapeReconciliation = production(
    "proxy-transport-mode",
    &[
        standalone(
            MaterializedProtocol::HttpProxy,
            NO_SECURITY_VARIANTS,
            MaterializedWrapper::HttpTransport,
            MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::HttpConnect),
        ),
        standalone(
            MaterializedProtocol::HttpProxy,
            FULL_STREAM_TLS_VARIANTS,
            MaterializedWrapper::HttpTransport,
            MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::HttpConnect),
        ),
    ],
);

pub(super) const INSECURE_SECURE_ENDPOINT_UNDERLAY: SourceShapeReconciliation = production(
    "insecure-secure-endpoint-underlay",
    &[standalone(
        MaterializedProtocol::HttpProxy,
        INSECURE_TLS_VARIANTS,
        MaterializedWrapper::None,
        MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::HttpConnect),
    )],
);

pub(super) const FINGERPRINT_SECURE_ENDPOINT_UNDERLAY: SourceShapeReconciliation = production(
    "fingerprint-secure-endpoint-underlay",
    &[standalone(
        MaterializedProtocol::HttpProxy,
        FINGERPRINT_AWARE_TLS_VARIANTS,
        MaterializedWrapper::None,
        MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::HttpConnect),
    )],
);

pub(super) const INSECURE_FRAME_STREAM_UNDERLAY: SourceShapeReconciliation = production(
    "insecure-frame-stream-underlay",
    &[standalone(
        MaterializedProtocol::AnyTls,
        INSECURE_TLS_VARIANTS,
        MaterializedWrapper::FrameStream,
        MaterializedUdp::AnyTls,
    )],
);

pub(super) const FULL_UTLS_SECURITY_UNDERLAY: SourceShapeReconciliation =
    deferred("full-utls-security-underlay");

pub(super) const TLS_FRAGMENT_SECURITY_UNDERLAY: SourceShapeReconciliation = aggregate(
    "tls-fragment-security-underlay",
    &[
        aggregate_component(
            "baseline-tls-auth-endpoint",
            SourceShapeProjection::TlsFragment,
        ),
        aggregate_component(
            "baseline-aead-framed-endpoint",
            SourceShapeProjection::TlsFragment,
        ),
        aggregate_component(
            "vless-native-tcp-endpoint",
            SourceShapeProjection::TlsFragment,
        ),
        aggregate_component(
            "baseline-tls-vision-endpoint",
            SourceShapeProjection::TlsFragment,
        ),
        aggregate_component(
            "baseline-frame-stream-endpoint",
            SourceShapeProjection::TlsFragment,
        ),
        aggregate_component(
            "stream-wrapper-websocket",
            SourceShapeProjection::TlsFragment,
        ),
        aggregate_component("stream-wrapper-grpc", SourceShapeProjection::TlsFragment),
        aggregate_component(
            "stream-wrapper-httpupgrade",
            SourceShapeProjection::TlsFragment,
        ),
        aggregate_component(
            "vless-meek-tls-stream-wrapper",
            SourceShapeProjection::TlsFragment,
        ),
        aggregate_component(
            "vless-h2-stream-wrapper",
            SourceShapeProjection::TlsFragment,
        ),
        aggregate_component(
            "vmess-h2-stream-wrapper",
            SourceShapeProjection::TlsFragment,
        ),
        aggregate_component("xhttp-h1-wrapper", SourceShapeProjection::TlsFragment),
        aggregate_component("stream-wrapper-xhttp", SourceShapeProjection::TlsFragment),
        aggregate_component(
            "secure-endpoint-capability",
            SourceShapeProjection::TlsFragment,
        ),
        aggregate_component(
            "secure-websocket-framed-endpoint",
            SourceShapeProjection::TlsFragment,
        ),
        aggregate_component(
            "secure-httpupgrade-framed-endpoint",
            SourceShapeProjection::TlsFragment,
        ),
        aggregate_component(
            "inner-encryption-stream-wrapper",
            SourceShapeProjection::TlsFragment,
        ),
        aggregate_component(
            "tls-websocket-plugin-wrapper",
            SourceShapeProjection::TlsFragment,
        ),
        aggregate_component("nested-chain-shape", SourceShapeProjection::TlsFragment),
        aggregate_component("proxy-transport-mode", SourceShapeProjection::TlsFragment),
        aggregate_component(
            "insecure-secure-endpoint-underlay",
            SourceShapeProjection::TlsFragment,
        ),
        aggregate_component(
            "fingerprint-secure-endpoint-underlay",
            SourceShapeProjection::TlsFragment,
        ),
        aggregate_component(
            "insecure-frame-stream-underlay",
            SourceShapeProjection::TlsFragment,
        ),
        aggregate_component("mux-transport-wrapper", SourceShapeProjection::TlsFragment),
    ],
);

pub(super) const SHARED_REALITY_SECURITY_UNDERLAY: SourceShapeReconciliation = aggregate(
    "shared-reality-security-underlay",
    &[
        aggregate_component("vless-native-tcp-endpoint", SourceShapeProjection::Reality),
        aggregate_component("reality-security-underlay", SourceShapeProjection::Reality),
        aggregate_component("stream-wrapper-websocket", SourceShapeProjection::Reality),
        aggregate_component("stream-wrapper-grpc", SourceShapeProjection::Reality),
        aggregate_component("stream-wrapper-httpupgrade", SourceShapeProjection::Reality),
        aggregate_component(
            "vless-meek-reality-stream-wrapper",
            SourceShapeProjection::Reality,
        ),
        aggregate_component("stream-wrapper-xhttp", SourceShapeProjection::Reality),
    ],
);

pub(super) const MUX_TRANSPORT_WRAPPER: SourceShapeReconciliation = production(
    "mux-transport-wrapper",
    &[standalone(
        MaterializedProtocol::VlessMux,
        FULL_STREAM_TLS_VARIANTS,
        MaterializedWrapper::Mux,
        MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::VlessMux),
    )],
);

pub(super) const PASSTHROUGH_UDP_TRANSPORT: SourceShapeReconciliation =
    deferred("passthrough-udp-transport");

pub(super) const LEGACY_CIPHER_PROTOCOL_SHAPE: SourceShapeReconciliation = production(
    "legacy-cipher-protocol-shape",
    &[standalone(
        MaterializedProtocol::ShadowsocksRHttpSimple,
        LEGACY_CIPHER_VARIANTS,
        MaterializedWrapper::LegacyObfs,
        MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::ShadowsocksR),
    )],
);

pub(super) const XHTTP_H3_WRAPPER: SourceShapeReconciliation = production(
    "xhttp-h3-wrapper",
    &[xhttp_h3(MaterializedXhttpSettings::Default)],
);

pub(super) const NON_NATIVE_ABI_OUTBOUND_SHAPE: SourceShapeReconciliation =
    rejected("non-native-abi-outbound-shape");

pub(super) const EXTERNAL_RUNTIME_DEPENDENT_SHAPE: SourceShapeReconciliation =
    rejected("external-runtime-dependent-shape");

pub(super) const NON_NATIVE_EXECUTOR_DEPENDENT_SHAPE: SourceShapeReconciliation =
    rejected("non-native-executor-dependent-shape");
