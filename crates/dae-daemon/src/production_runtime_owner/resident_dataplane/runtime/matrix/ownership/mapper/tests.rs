use super::*;

#[test]
fn every_protocol_shape_has_a_deliberate_valid_ownership_tuple() {
    use PolicyClosedDimension as Closed;
    use SecurityDimension as Security;
    use StreamPacketDimension as Stream;
    use UdpDimension as Udp;
    use WrapperDimension as Wrapper;

    let cases = [
        (
            shape(
                Protocol::VlessStandard,
                Security::None,
                Wrapper::None,
                Udp::Vless(Stream::PlainTcp),
            ),
            FLOW_STREAM_PACKET_OWNERSHIP,
        ),
        (
            shape(
                Protocol::VlessVision,
                Security::StandardTls,
                Wrapper::None,
                Udp::VlessVision,
            ),
            FLOW_STREAM_PACKET_OWNERSHIP,
        ),
        (
            shape(
                Protocol::VlessStandard,
                Security::QuicTls,
                Wrapper::XhttpH3,
                Udp::Vless(Stream::XhttpH3),
            ),
            CONFIGURED_HTTP_OWNERSHIP,
        ),
        (
            shape(
                Protocol::VlessMux,
                Security::StandardTls,
                Wrapper::Mux,
                Udp::PolicyClosed(Closed::VlessMux),
            ),
            GENERATION_OWNED_VLESS_MUX_OWNERSHIP,
        ),
        (
            shape(
                Protocol::Socks5,
                Security::None,
                Wrapper::None,
                Udp::Socks5Associate,
            ),
            FLOW_STREAM_ASSOCIATION_OWNERSHIP,
        ),
        (
            shape(
                Protocol::HttpProxy,
                Security::None,
                Wrapper::None,
                Udp::PolicyClosed(Closed::HttpConnect),
            ),
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
        ),
        (
            shape(
                Protocol::ShadowsocksAead,
                Security::Aead,
                Wrapper::None,
                Udp::ShadowsocksAead,
            ),
            FLOW_STREAM_PACKET_OWNERSHIP,
        ),
        (
            shape(
                Protocol::Shadowsocks2022,
                Security::Aead2022,
                Wrapper::None,
                Udp::Shadowsocks2022,
            ),
            FLOW_STREAM_PACKET_OWNERSHIP,
        ),
        (
            shape(
                Protocol::ShadowsocksSimpleObfsHttp,
                Security::Aead,
                Wrapper::SimpleObfsHttp,
                Udp::PolicyClosed(Closed::PluginWrapper),
            ),
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
        ),
        (
            shape(
                Protocol::ShadowsocksSimpleObfsTls,
                Security::Aead,
                Wrapper::SimpleObfsTls,
                Udp::PolicyClosed(Closed::PluginWrapper),
            ),
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
        ),
        (
            shape(
                Protocol::ShadowsocksV2rayPluginTlsWebSocket,
                Security::StandardTls,
                Wrapper::V2rayPluginTlsWebSocket,
                Udp::PolicyClosed(Closed::PluginWrapper),
            ),
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
        ),
        (
            shape(
                Protocol::Shadowsocks2022SimpleObfsHttp,
                Security::Aead2022,
                Wrapper::SimpleObfsHttp,
                Udp::PolicyClosed(Closed::PluginWrapper),
            ),
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
        ),
        (
            shape(
                Protocol::ShadowsocksRHttpSimple,
                Security::LegacyCipher,
                Wrapper::LegacyObfs,
                Udp::PolicyClosed(Closed::ShadowsocksR),
            ),
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
        ),
        (
            shape(
                Protocol::Trojan,
                Security::StandardTls,
                Wrapper::None,
                Udp::Trojan(Stream::TlsTcp),
            ),
            FLOW_STREAM_PACKET_OWNERSHIP,
        ),
        (
            shape(
                Protocol::TrojanInnerShadowsocks,
                Security::StandardTls,
                Wrapper::WebSocket,
                Udp::PolicyClosed(Closed::TrojanInnerShadowsocks),
            ),
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
        ),
        (
            shape(
                Protocol::AnyTls,
                Security::StandardTls,
                Wrapper::FrameStream,
                Udp::AnyTls,
            ),
            FLOW_STREAM_PACKET_OWNERSHIP,
        ),
        (
            shape(
                Protocol::VmessAead,
                Security::None,
                Wrapper::None,
                Udp::Vmess(Stream::PlainTcp),
            ),
            FLOW_STREAM_PACKET_OWNERSHIP,
        ),
        (
            shape(
                Protocol::Hysteria2,
                Security::QuicTls,
                Wrapper::QuicStream,
                Udp::Hysteria2,
            ),
            GENERATION_OWNED_HYSTERIA2_OWNERSHIP,
        ),
        (
            shape(
                Protocol::Tuic,
                Security::QuicTls,
                Wrapper::QuicStream,
                Udp::Tuic,
            ),
            GENERATION_OWNED_TUIC_OWNERSHIP,
        ),
        (
            shape(
                Protocol::Juicity,
                Security::QuicTls,
                Wrapper::QuicStream,
                Udp::Juicity,
            ),
            GENERATION_OWNED_JUICITY_OWNERSHIP,
        ),
    ];

    for (shape, expected) in cases {
        assert_eq!(profile_for_shape(shape), Some(expected), "{shape:?}");
    }
}

const fn shape(
    protocol: Protocol,
    security: SecurityDimension,
    wrapper: WrapperDimension,
    udp: UdpDimension,
) -> TypedOwnershipShape {
    TypedOwnershipShape {
        protocol,
        security,
        wrapper,
        udp,
    }
}
