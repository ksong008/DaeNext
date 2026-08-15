use super::*;

#[test]
fn raw_tls_security_variants_follow_builder_reachability() {
    use PolicyClosedDimension as Closed;
    use SecurityDimension as Security;
    use StreamPacketDimension as Stream;
    use UdpDimension as Udp;
    use WrapperDimension as Wrapper;

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
        let trojan = shape(
            Protocol::Trojan,
            security,
            Wrapper::WebSocket,
            Udp::Trojan(Stream::WebSocketTls),
        );
        assert_eq!(
            profile_for_shape(trojan),
            Some(FLOW_STREAM_PACKET_OWNERSHIP),
            "{trojan:?}"
        );
        let inner = shape(
            Protocol::TrojanInnerShadowsocks,
            security,
            Wrapper::WebSocket,
            Udp::PolicyClosed(Closed::TrojanInnerShadowsocks),
        );
        assert_eq!(
            profile_for_shape(inner),
            Some(FLOW_STREAM_POLICY_CLOSED_OWNERSHIP),
            "{inner:?}"
        );
        let anytls = shape(
            Protocol::AnyTls,
            security,
            Wrapper::FrameStream,
            Udp::AnyTls,
        );
        assert_eq!(
            profile_for_shape(anytls),
            Some(GENERATION_OWNED_ANYTLS_OWNERSHIP),
            "{anytls:?}"
        );
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
