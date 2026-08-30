use super::constructors::*;
use super::selector_sets::*;
use super::*;

pub(super) const BASELINE_AEAD_CIPHER_ENDPOINT: SourceShapeReconciliation = production(
    "baseline-aead-cipher-endpoint",
    &[standalone(
        MaterializedProtocol::ShadowsocksAead,
        AEAD_VARIANTS,
        MaterializedWrapper::None,
        MaterializedUdp::ShadowsocksAead,
    )],
);

pub(super) const BASELINE_AEAD_2022_CIPHER_ENDPOINT: SourceShapeReconciliation = production(
    "baseline-aead-2022-cipher-endpoint",
    &[standalone(
        MaterializedProtocol::Shadowsocks2022,
        AEAD_2022_VARIANTS,
        MaterializedWrapper::None,
        MaterializedUdp::Shadowsocks2022,
    )],
);

pub(super) const BASELINE_TLS_AUTH_ENDPOINT: SourceShapeReconciliation = production(
    "baseline-tls-auth-endpoint",
    &[standalone(
        MaterializedProtocol::Trojan,
        FULL_STREAM_TLS_VARIANTS,
        MaterializedWrapper::None,
        MaterializedUdp::Trojan(MaterializedStreamPacketTransport::TlsTcp),
    )],
);

pub(super) const BASELINE_AEAD_FRAMED_ENDPOINT: SourceShapeReconciliation = production(
    "baseline-aead-framed-endpoint",
    &[
        standalone(
            MaterializedProtocol::VmessAead,
            NO_SECURITY_VARIANTS,
            MaterializedWrapper::None,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::PlainTcp),
        ),
        standalone(
            MaterializedProtocol::VmessAead,
            FULL_STREAM_TLS_VARIANTS,
            MaterializedWrapper::None,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::TlsTcp),
        ),
        standalone(
            MaterializedProtocol::VmessAead,
            NO_SECURITY_VARIANTS,
            MaterializedWrapper::TcpHttpHeader,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::TcpHttpHeaderPlain),
        ),
        standalone(
            MaterializedProtocol::VmessAead,
            FULL_STREAM_TLS_VARIANTS,
            MaterializedWrapper::TcpHttpHeader,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::TcpHttpHeaderTls),
        ),
    ],
);

pub(super) const VLESS_NATIVE_TCP_ENDPOINT: SourceShapeReconciliation = production(
    "vless-native-tcp-endpoint",
    &[
        standalone(
            MaterializedProtocol::VlessStandard,
            NO_SECURITY_VARIANTS,
            MaterializedWrapper::None,
            MaterializedUdp::Vless(MaterializedStreamPacketTransport::PlainTcp),
        ),
        standalone(
            MaterializedProtocol::VlessStandard,
            FULL_STREAM_TLS_AND_REALITY_VARIANTS,
            MaterializedWrapper::None,
            MaterializedUdp::Vless(MaterializedStreamPacketTransport::TlsTcp),
        ),
    ],
);

pub(super) const BASELINE_TLS_VISION_ENDPOINT: SourceShapeReconciliation = production(
    "baseline-tls-vision-endpoint",
    &[standalone(
        MaterializedProtocol::VlessVision,
        FULL_STREAM_TLS_VARIANTS,
        MaterializedWrapper::None,
        MaterializedUdp::VlessVision,
    )],
);

pub(super) const BASELINE_QUIC_AUTH_ENDPOINT: SourceShapeReconciliation = production(
    "baseline-quic-auth-endpoint",
    &[quic(
        MaterializedProtocol::Hysteria2,
        MaterializedUdp::Hysteria2,
        ALL_QUIC_VERIFICATION,
        MaterializedPortHopping::Disabled,
    )],
);

pub(super) const BASELINE_QUIC_UUID_ENDPOINT: SourceShapeReconciliation = production(
    "baseline-quic-uuid-endpoint",
    &[quic(
        MaterializedProtocol::Tuic,
        MaterializedUdp::Tuic,
        &[
            MaterializedQuicVerification::WebPki,
            MaterializedQuicVerification::Insecure,
        ],
        MaterializedPortHopping::NotApplicable,
    )],
);

pub(super) const BASELINE_QUIC_PASSWORD_ENDPOINT: SourceShapeReconciliation = production(
    "baseline-quic-password-endpoint",
    &[quic(
        MaterializedProtocol::Juicity,
        MaterializedUdp::Juicity,
        ALL_QUIC_VERIFICATION,
        MaterializedPortHopping::NotApplicable,
    )],
);

pub(super) const BASELINE_FRAME_STREAM_ENDPOINT: SourceShapeReconciliation = production(
    "baseline-frame-stream-endpoint",
    &[standalone(
        MaterializedProtocol::AnyTls,
        STANDARD_OR_FRAGMENTED_TLS_VARIANTS,
        MaterializedWrapper::FrameStream,
        MaterializedUdp::AnyTls,
    )],
);

pub(super) const BASELINE_CONNECT_ENDPOINT: SourceShapeReconciliation = production(
    "baseline-connect-endpoint",
    &[standalone(
        MaterializedProtocol::HttpProxy,
        NO_SECURITY_VARIANTS,
        MaterializedWrapper::None,
        MaterializedUdp::PolicyClosed(MaterializedPolicyClosedReason::HttpConnect),
    )],
);

pub(super) const BASELINE_SOCKS_ENDPOINT: SourceShapeReconciliation = production(
    "baseline-socks-endpoint",
    &[standalone(
        MaterializedProtocol::Socks5,
        NO_SECURITY_VARIANTS,
        MaterializedWrapper::None,
        MaterializedUdp::Socks5Associate,
    )],
);

pub(super) const CONNECT_UDP_H2_ENDPOINT: SourceShapeReconciliation =
    rejected("connect-udp-h2-endpoint");

pub(super) const CONNECT_UDP_H3_ENDPOINT: SourceShapeReconciliation =
    rejected("connect-udp-h3-endpoint");
