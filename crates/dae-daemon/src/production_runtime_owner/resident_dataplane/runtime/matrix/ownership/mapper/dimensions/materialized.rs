use super::*;
use dae_outbound::{
    MaterializedExecutionShape, MaterializedPolicyClosedReason, MaterializedProtocol,
    MaterializedSecurity, MaterializedStreamPacketTransport, MaterializedUdp, MaterializedWrapper,
};

pub(in super::super) fn project_materialized_execution_shape(
    execution: plan::ResidentExecutionPlan,
) -> MaterializedExecutionShape {
    let shape = TypedOwnershipShape::from_execution(execution);
    MaterializedExecutionShape {
        protocol: materialized_protocol(shape.protocol),
        security: materialized_security(shape.security),
        wrapper: materialized_wrapper(shape.wrapper),
        udp: materialized_udp(shape.udp),
    }
}

fn materialized_protocol(protocol: Protocol) -> MaterializedProtocol {
    match protocol {
        Protocol::VlessStandard => MaterializedProtocol::VlessStandard,
        Protocol::VlessVision => MaterializedProtocol::VlessVision,
        Protocol::VlessMux => MaterializedProtocol::VlessMux,
        Protocol::Socks5 => MaterializedProtocol::Socks5,
        Protocol::HttpProxy => MaterializedProtocol::HttpProxy,
        Protocol::ShadowsocksAead => MaterializedProtocol::ShadowsocksAead,
        Protocol::Shadowsocks2022 => MaterializedProtocol::Shadowsocks2022,
        Protocol::ShadowsocksSimpleObfsHttp => MaterializedProtocol::ShadowsocksSimpleObfsHttp,
        Protocol::ShadowsocksSimpleObfsTls => MaterializedProtocol::ShadowsocksSimpleObfsTls,
        Protocol::ShadowsocksV2rayPluginTlsWebSocket => {
            MaterializedProtocol::ShadowsocksV2rayPluginTlsWebSocket
        }
        Protocol::Shadowsocks2022SimpleObfsHttp => {
            MaterializedProtocol::Shadowsocks2022SimpleObfsHttp
        }
        Protocol::ShadowsocksRHttpSimple => MaterializedProtocol::ShadowsocksRHttpSimple,
        Protocol::Trojan => MaterializedProtocol::Trojan,
        Protocol::TrojanInnerShadowsocks => MaterializedProtocol::TrojanInnerShadowsocks,
        Protocol::AnyTls => MaterializedProtocol::AnyTls,
        Protocol::VmessAead => MaterializedProtocol::VmessAead,
        Protocol::Hysteria2 => MaterializedProtocol::Hysteria2,
        Protocol::Tuic => MaterializedProtocol::Tuic,
        Protocol::Juicity => MaterializedProtocol::Juicity,
    }
}

fn materialized_security(security: SecurityDimension) -> MaterializedSecurity {
    match security {
        SecurityDimension::None => MaterializedSecurity::None,
        SecurityDimension::Aead => MaterializedSecurity::Aead,
        SecurityDimension::Aead2022 => MaterializedSecurity::Aead2022,
        SecurityDimension::LegacyCipher => MaterializedSecurity::LegacyCipher,
        SecurityDimension::StandardTls => MaterializedSecurity::StandardTls,
        SecurityDimension::InsecureTls => MaterializedSecurity::InsecureTls,
        SecurityDimension::FragmentedTls => MaterializedSecurity::FragmentedTls,
        SecurityDimension::FingerprintAwareTls => MaterializedSecurity::FingerprintAwareTls,
        SecurityDimension::RealityRustls => MaterializedSecurity::RealityRustls,
        SecurityDimension::RealityFingerprint => MaterializedSecurity::RealityFingerprint,
        SecurityDimension::QuicTls => MaterializedSecurity::QuicTls,
        SecurityDimension::Unsupported => MaterializedSecurity::Unsupported,
    }
}

fn materialized_wrapper(wrapper: WrapperDimension) -> MaterializedWrapper {
    match wrapper {
        WrapperDimension::None => MaterializedWrapper::None,
        WrapperDimension::HttpTransport => MaterializedWrapper::HttpTransport,
        WrapperDimension::WebSocket => MaterializedWrapper::WebSocket,
        WrapperDimension::HttpUpgrade => MaterializedWrapper::HttpUpgrade,
        WrapperDimension::Grpc => MaterializedWrapper::Grpc,
        WrapperDimension::H2 => MaterializedWrapper::H2,
        WrapperDimension::Meek => MaterializedWrapper::Meek,
        WrapperDimension::Mux => MaterializedWrapper::Mux,
        WrapperDimension::XhttpH1 => MaterializedWrapper::XhttpH1,
        WrapperDimension::XhttpH2 => MaterializedWrapper::XhttpH2,
        WrapperDimension::XhttpH3 => MaterializedWrapper::XhttpH3,
        WrapperDimension::FrameStream => MaterializedWrapper::FrameStream,
        WrapperDimension::QuicStream => MaterializedWrapper::QuicStream,
        WrapperDimension::SimpleObfsHttp => MaterializedWrapper::SimpleObfsHttp,
        WrapperDimension::SimpleObfsTls => MaterializedWrapper::SimpleObfsTls,
        WrapperDimension::LegacyObfs => MaterializedWrapper::LegacyObfs,
        WrapperDimension::V2rayPluginTlsWebSocket => MaterializedWrapper::V2rayPluginTlsWebSocket,
        WrapperDimension::Unsupported => MaterializedWrapper::Unsupported,
    }
}

fn materialized_udp(udp: UdpDimension) -> MaterializedUdp {
    match udp {
        UdpDimension::Socks5Associate => MaterializedUdp::Socks5Associate,
        UdpDimension::ShadowsocksAead => MaterializedUdp::ShadowsocksAead,
        UdpDimension::Shadowsocks2022 => MaterializedUdp::Shadowsocks2022,
        UdpDimension::Vless(transport) => MaterializedUdp::Vless(materialized_stream(transport)),
        UdpDimension::VlessVision => MaterializedUdp::VlessVision,
        UdpDimension::Trojan(transport) => MaterializedUdp::Trojan(materialized_stream(transport)),
        UdpDimension::Vmess(transport) => MaterializedUdp::Vmess(materialized_stream(transport)),
        UdpDimension::AnyTls => MaterializedUdp::AnyTls,
        UdpDimension::Hysteria2 => MaterializedUdp::Hysteria2,
        UdpDimension::Tuic => MaterializedUdp::Tuic,
        UdpDimension::Juicity => MaterializedUdp::Juicity,
        UdpDimension::PolicyClosed(reason) => {
            MaterializedUdp::PolicyClosed(materialized_policy_closed(reason))
        }
    }
}

fn materialized_stream(transport: StreamPacketDimension) -> MaterializedStreamPacketTransport {
    match transport {
        StreamPacketDimension::PlainTcp => MaterializedStreamPacketTransport::PlainTcp,
        StreamPacketDimension::TlsTcp => MaterializedStreamPacketTransport::TlsTcp,
        StreamPacketDimension::WebSocketPlain => MaterializedStreamPacketTransport::WebSocketPlain,
        StreamPacketDimension::WebSocketTls => MaterializedStreamPacketTransport::WebSocketTls,
        StreamPacketDimension::HttpUpgradePlain => {
            MaterializedStreamPacketTransport::HttpUpgradePlain
        }
        StreamPacketDimension::HttpUpgradeTls => MaterializedStreamPacketTransport::HttpUpgradeTls,
        StreamPacketDimension::GrpcTls => MaterializedStreamPacketTransport::GrpcTls,
        StreamPacketDimension::H2Tls => MaterializedStreamPacketTransport::H2Tls,
        StreamPacketDimension::XhttpH1 => MaterializedStreamPacketTransport::XhttpH1,
        StreamPacketDimension::XhttpH2 => MaterializedStreamPacketTransport::XhttpH2,
        StreamPacketDimension::XhttpH3 => MaterializedStreamPacketTransport::XhttpH3,
    }
}

fn materialized_policy_closed(reason: PolicyClosedDimension) -> MaterializedPolicyClosedReason {
    match reason {
        PolicyClosedDimension::HttpConnect => MaterializedPolicyClosedReason::HttpConnect,
        PolicyClosedDimension::PluginWrapper => MaterializedPolicyClosedReason::PluginWrapper,
        PolicyClosedDimension::ShadowsocksR => MaterializedPolicyClosedReason::ShadowsocksR,
        PolicyClosedDimension::TrojanInnerShadowsocks => {
            MaterializedPolicyClosedReason::TrojanInnerShadowsocks
        }
        PolicyClosedDimension::TrojanUnsupportedWrapper => {
            MaterializedPolicyClosedReason::TrojanUnsupportedWrapper
        }
        PolicyClosedDimension::VlessMux => MaterializedPolicyClosedReason::VlessMux,
        PolicyClosedDimension::VlessMeek => MaterializedPolicyClosedReason::VlessMeek,
        PolicyClosedDimension::VlessUnsupportedShape => {
            MaterializedPolicyClosedReason::VlessUnsupportedShape
        }
        PolicyClosedDimension::VmessH2 => MaterializedPolicyClosedReason::VmessH2,
        PolicyClosedDimension::VmessUnsupportedShape => {
            MaterializedPolicyClosedReason::VmessUnsupportedShape
        }
    }
}
