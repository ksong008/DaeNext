use super::*;

#[test]
fn raw_tls_security_variants_follow_builder_reachability() {
    use PolicyClosedDimension as Closed;
    use SecurityDimension as Security;
    use StreamPacketDimension as Stream;
    use UdpDimension as Udp;
    use WrapperDimension as Wrapper;

    for security in [Security::StandardTls, Security::InsecureTls] {
        let shape = shape(
            Protocol::ConnectUdpH2,
            security,
            Wrapper::ConnectUdpH2,
            Udp::ConnectUdpH2,
        );
        assert_eq!(
            profile_for_shape(shape),
            Some(GENERATION_CONNECT_UDP_OWNERSHIP),
            "{shape:?}"
        );
    }

    for security in [Security::StandardTls, Security::FragmentedTls] {
        let shape = shape(
            Protocol::ShadowsocksV2rayPluginTlsWebSocket,
            security,
            Wrapper::V2rayPluginTlsWebSocket,
            Udp::PolicyClosed(Closed::PluginWrapper),
        );
        assert_eq!(
            profile_for_shape(shape),
            Some(FLOW_STREAM_POLICY_CLOSED_OWNERSHIP),
            "{shape:?}"
        );
    }

    for security in [
        Security::StandardTls,
        Security::InsecureTls,
        Security::FragmentedTls,
    ] {
        for (shape, expected) in [
            (
                shape(
                    Protocol::Trojan,
                    security,
                    Wrapper::WebSocket,
                    Udp::Trojan(Stream::WebSocketTls),
                ),
                FLOW_STREAM_PACKET_OWNERSHIP,
            ),
            (
                shape(
                    Protocol::TrojanInnerShadowsocks,
                    security,
                    Wrapper::WebSocket,
                    Udp::PolicyClosed(Closed::TrojanInnerShadowsocks),
                ),
                FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
            ),
            (
                shape(
                    Protocol::AnyTls,
                    security,
                    Wrapper::FrameStream,
                    Udp::AnyTls,
                ),
                FLOW_STREAM_PACKET_OWNERSHIP,
            ),
        ] {
            assert_eq!(profile_for_shape(shape), Some(expected), "{shape:?}");
        }
    }

    let fingerprinted_plain_trojan = shape(
        Protocol::Trojan,
        Security::FingerprintAwareTls,
        Wrapper::None,
        Udp::Trojan(Stream::TlsTcp),
    );
    assert_eq!(
        profile_for_shape(fingerprinted_plain_trojan),
        Some(FLOW_STREAM_PACKET_OWNERSHIP)
    );
}

#[test]
fn builder_unreachable_tls_security_variants_are_rejected() {
    use PolicyClosedDimension as Closed;
    use SecurityDimension as Security;
    use StreamPacketDimension as Stream;
    use UdpDimension as Udp;
    use WrapperDimension as Wrapper;

    let impossible = [
        shape(
            Protocol::ConnectUdpH2,
            Security::FragmentedTls,
            Wrapper::ConnectUdpH2,
            Udp::ConnectUdpH2,
        ),
        shape(
            Protocol::ConnectUdpH2,
            Security::FingerprintAwareTls,
            Wrapper::ConnectUdpH2,
            Udp::ConnectUdpH2,
        ),
        shape(
            Protocol::ShadowsocksV2rayPluginTlsWebSocket,
            Security::InsecureTls,
            Wrapper::V2rayPluginTlsWebSocket,
            Udp::PolicyClosed(Closed::PluginWrapper),
        ),
        shape(
            Protocol::ShadowsocksV2rayPluginTlsWebSocket,
            Security::FingerprintAwareTls,
            Wrapper::V2rayPluginTlsWebSocket,
            Udp::PolicyClosed(Closed::PluginWrapper),
        ),
        shape(
            Protocol::Trojan,
            Security::FingerprintAwareTls,
            Wrapper::WebSocket,
            Udp::Trojan(Stream::WebSocketTls),
        ),
        shape(
            Protocol::TrojanInnerShadowsocks,
            Security::FingerprintAwareTls,
            Wrapper::WebSocket,
            Udp::PolicyClosed(Closed::TrojanInnerShadowsocks),
        ),
        shape(
            Protocol::AnyTls,
            Security::FingerprintAwareTls,
            Wrapper::FrameStream,
            Udp::AnyTls,
        ),
    ];

    for shape in impossible {
        assert_eq!(profile_for_shape(shape), None, "{shape:?}");
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
