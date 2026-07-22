use super::*;

#[path = "dimensions/materialized.rs"]
mod materialized;

pub(super) use self::materialized::project_materialized_execution_shape;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TypedOwnershipShape {
    pub(super) protocol: Protocol,
    pub(super) security: SecurityDimension,
    pub(super) wrapper: WrapperDimension,
    pub(super) udp: UdpDimension,
}

impl TypedOwnershipShape {
    pub(super) fn from_execution(execution: plan::ResidentExecutionPlan) -> Self {
        Self {
            protocol: execution.protocol,
            security: security_dimension(execution.security),
            wrapper: wrapper_dimension(execution.wrapper),
            udp: udp_dimension(execution.udp),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SecurityDimension {
    None,
    Aead,
    Aead2022,
    LegacyCipher,
    StandardTls,
    InsecureTls,
    FragmentedTls,
    FingerprintAwareTls,
    RealityRustls,
    RealityFingerprint,
    QuicTls,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WrapperDimension {
    None,
    TcpHttpHeader,
    HttpTransport,
    WebSocket,
    HttpUpgrade,
    Grpc,
    H2,
    Meek,
    Mux,
    XhttpH1,
    XhttpH2,
    XhttpH3,
    FrameStream,
    QuicStream,
    SimpleObfsHttp,
    SimpleObfsTls,
    LegacyObfs,
    V2rayPluginTlsWebSocket,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StreamPacketDimension {
    PlainTcp,
    TlsTcp,
    TcpHttpHeaderPlain,
    TcpHttpHeaderTls,
    WebSocketPlain,
    WebSocketTls,
    HttpUpgradePlain,
    HttpUpgradeTls,
    GrpcTls,
    H2Tls,
    XhttpH1,
    XhttpH2,
    XhttpH3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UdpDimension {
    Socks5Associate,
    ShadowsocksAead,
    Shadowsocks2022,
    Vless(StreamPacketDimension),
    VlessVision,
    Trojan(StreamPacketDimension),
    Vmess(StreamPacketDimension),
    AnyTls,
    Hysteria2,
    Tuic,
    Juicity,
    PolicyClosed(PolicyClosedDimension),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PolicyClosedDimension {
    HttpConnect,
    PluginWrapper,
    ShadowsocksR,
    TrojanInnerShadowsocks,
    TrojanUnsupportedWrapper,
    VlessMux,
    VlessMeek,
    VlessUnsupportedShape,
    VmessH2,
    VmessUnsupportedShape,
}

fn security_dimension(security: plan::ResidentSecurityUnderlayPlan) -> SecurityDimension {
    use plan::ResidentSecurityUnderlayPlan as Security;

    match security {
        Security::None => SecurityDimension::None,
        Security::Aead => SecurityDimension::Aead,
        Security::Aead2022 => SecurityDimension::Aead2022,
        Security::LegacyCipher => SecurityDimension::LegacyCipher,
        Security::StandardTls => SecurityDimension::StandardTls,
        Security::InsecureTls => SecurityDimension::InsecureTls,
        Security::FragmentedTls => SecurityDimension::FragmentedTls,
        Security::FingerprintAwareTls => SecurityDimension::FingerprintAwareTls,
        Security::RealityRustls => SecurityDimension::RealityRustls,
        Security::RealityFingerprint => SecurityDimension::RealityFingerprint,
        Security::QuicTls => SecurityDimension::QuicTls,
        Security::Unsupported => SecurityDimension::Unsupported,
    }
}

fn wrapper_dimension(wrapper: plan::ResidentStreamWrapperPlan) -> WrapperDimension {
    use plan::ResidentStreamWrapperPlan as Wrapper;
    use plan::ResidentXhttpHttpVersion as Xhttp;

    match wrapper {
        Wrapper::None => WrapperDimension::None,
        Wrapper::TcpHttpHeader => WrapperDimension::TcpHttpHeader,
        Wrapper::HttpTransport => WrapperDimension::HttpTransport,
        Wrapper::WebSocket => WrapperDimension::WebSocket,
        Wrapper::HttpUpgrade => WrapperDimension::HttpUpgrade,
        Wrapper::Grpc => WrapperDimension::Grpc,
        Wrapper::H2 => WrapperDimension::H2,
        Wrapper::Meek => WrapperDimension::Meek,
        Wrapper::Mux => WrapperDimension::Mux,
        Wrapper::Xhttp(version) => match version {
            Xhttp::H1 => WrapperDimension::XhttpH1,
            Xhttp::H2 => WrapperDimension::XhttpH2,
            Xhttp::H3 => WrapperDimension::XhttpH3,
        },
        Wrapper::FrameStream => WrapperDimension::FrameStream,
        Wrapper::QuicStream => WrapperDimension::QuicStream,
        Wrapper::SimpleObfsHttp => WrapperDimension::SimpleObfsHttp,
        Wrapper::SimpleObfsTls => WrapperDimension::SimpleObfsTls,
        Wrapper::LegacyObfs => WrapperDimension::LegacyObfs,
        Wrapper::V2rayPluginTlsWebSocket => WrapperDimension::V2rayPluginTlsWebSocket,
        Wrapper::Unsupported => WrapperDimension::Unsupported,
    }
}

fn udp_dimension(udp: plan::ResidentUdpExecutorFactory) -> UdpDimension {
    use plan::ResidentUdpExecutorFactory as Udp;

    match udp {
        Udp::Socks5Associate => UdpDimension::Socks5Associate,
        Udp::ShadowsocksAead => UdpDimension::ShadowsocksAead,
        Udp::Shadowsocks2022 => UdpDimension::Shadowsocks2022,
        Udp::VlessStandard(transport) => UdpDimension::Vless(stream_packet_dimension(transport)),
        Udp::VlessVisionXudp => UdpDimension::VlessVision,
        Udp::Trojan(transport) => UdpDimension::Trojan(stream_packet_dimension(transport)),
        Udp::Vmess(transport) => UdpDimension::Vmess(stream_packet_dimension(transport)),
        Udp::AnyTlsPacketStream => UdpDimension::AnyTls,
        Udp::Hysteria2Datagram => UdpDimension::Hysteria2,
        Udp::TuicPacket => UdpDimension::Tuic,
        Udp::JuicityStreamPacket => UdpDimension::Juicity,
        Udp::PolicyClosed(reason) => UdpDimension::PolicyClosed(policy_closed_dimension(reason)),
    }
}

fn policy_closed_dimension(reason: plan::ResidentUdpPolicyClosedReason) -> PolicyClosedDimension {
    use plan::ResidentUdpPolicyClosedReason as Reason;

    match reason {
        Reason::HttpConnect => PolicyClosedDimension::HttpConnect,
        Reason::PluginWrapper => PolicyClosedDimension::PluginWrapper,
        Reason::ShadowsocksR => PolicyClosedDimension::ShadowsocksR,
        Reason::TrojanInnerShadowsocks => PolicyClosedDimension::TrojanInnerShadowsocks,
        Reason::TrojanUnsupportedWrapper => PolicyClosedDimension::TrojanUnsupportedWrapper,
        Reason::VlessMux => PolicyClosedDimension::VlessMux,
        Reason::VlessMeek => PolicyClosedDimension::VlessMeek,
        Reason::VlessUnsupportedShape => PolicyClosedDimension::VlessUnsupportedShape,
        Reason::VmessH2 => PolicyClosedDimension::VmessH2,
        Reason::VmessUnsupportedShape => PolicyClosedDimension::VmessUnsupportedShape,
    }
}

fn stream_packet_dimension(
    transport: plan::ResidentStreamPacketTransport,
) -> StreamPacketDimension {
    use plan::ResidentStreamPacketTransport as Stream;

    match transport {
        Stream::PlainTcp => StreamPacketDimension::PlainTcp,
        Stream::TlsTcp => StreamPacketDimension::TlsTcp,
        Stream::TcpHttpHeaderPlain => StreamPacketDimension::TcpHttpHeaderPlain,
        Stream::TcpHttpHeaderTls => StreamPacketDimension::TcpHttpHeaderTls,
        Stream::WebSocketPlain => StreamPacketDimension::WebSocketPlain,
        Stream::WebSocketTls => StreamPacketDimension::WebSocketTls,
        Stream::HttpUpgradePlain => StreamPacketDimension::HttpUpgradePlain,
        Stream::HttpUpgradeTls => StreamPacketDimension::HttpUpgradeTls,
        Stream::GrpcTls => StreamPacketDimension::GrpcTls,
        Stream::H2Tls => StreamPacketDimension::H2Tls,
        Stream::XhttpH1 => StreamPacketDimension::XhttpH1,
        Stream::XhttpH2 => StreamPacketDimension::XhttpH2,
        Stream::XhttpH3 => StreamPacketDimension::XhttpH3,
    }
}
