use super::*;

#[test]
fn factory_only_vless_plain_wrappers_are_not_materialized_shapes() {
    use SecurityDimension as Security;
    use StreamPacketDimension as Stream;
    use UdpDimension as Udp;
    use WrapperDimension as Wrapper;

    for shape in [
        shape(
            Protocol::VlessStandard,
            Security::None,
            Wrapper::WebSocket,
            Udp::Vless(Stream::WebSocketPlain),
        ),
        shape(
            Protocol::VlessStandard,
            Security::None,
            Wrapper::HttpUpgrade,
            Udp::Vless(Stream::HttpUpgradePlain),
        ),
    ] {
        assert_eq!(profile_for_shape(shape), None, "{shape:?}");
    }
}

#[test]
fn legal_tcp_with_policy_closed_udp_keeps_its_flow_ownership() {
    use PolicyClosedDimension as Closed;
    use SecurityDimension as Security;
    use UdpDimension as Udp;
    use WrapperDimension as Wrapper;

    let meek = shape(
        Protocol::VlessStandard,
        Security::StandardTls,
        Wrapper::Meek,
        Udp::PolicyClosed(Closed::VlessMeek),
    );
    assert_eq!(
        profile_for_shape(meek),
        Some(GENERATION_OWNED_MEEK_OWNERSHIP)
    );

    let cases = [
        shape(
            Protocol::VlessMux,
            Security::StandardTls,
            Wrapper::Mux,
            Udp::PolicyClosed(Closed::VlessMux),
        ),
        shape(
            Protocol::VmessAead,
            Security::StandardTls,
            Wrapper::H2,
            Udp::PolicyClosed(Closed::VmessH2),
        ),
        shape(
            Protocol::TrojanInnerShadowsocks,
            Security::StandardTls,
            Wrapper::WebSocket,
            Udp::PolicyClosed(Closed::TrojanInnerShadowsocks),
        ),
    ];

    for shape in cases {
        assert_eq!(
            profile_for_shape(shape),
            Some(FLOW_STREAM_POLICY_CLOSED_OWNERSHIP),
            "{shape:?}"
        );
    }
}

#[test]
fn policy_closed_reasons_cannot_cross_protocol_boundaries() {
    use PolicyClosedDimension as Closed;
    use SecurityDimension as Security;
    use UdpDimension as Udp;
    use WrapperDimension as Wrapper;

    let impossible = [
        shape(
            Protocol::HttpProxy,
            Security::None,
            Wrapper::None,
            Udp::PolicyClosed(Closed::VlessMeek),
        ),
        shape(
            Protocol::VlessStandard,
            Security::StandardTls,
            Wrapper::Meek,
            Udp::PolicyClosed(Closed::HttpConnect),
        ),
        shape(
            Protocol::VmessAead,
            Security::StandardTls,
            Wrapper::H2,
            Udp::PolicyClosed(Closed::VlessMux),
        ),
        shape(
            Protocol::TrojanInnerShadowsocks,
            Security::StandardTls,
            Wrapper::WebSocket,
            Udp::PolicyClosed(Closed::PluginWrapper),
        ),
    ];

    for shape in impossible {
        assert_eq!(profile_for_shape(shape), None, "{shape:?}");
    }
}

#[test]
fn unsupported_policy_closed_reasons_do_not_preserve_materialization() {
    use PolicyClosedDimension as Closed;
    use SecurityDimension as Security;
    use UdpDimension as Udp;
    use WrapperDimension as Wrapper;

    let unsupported = [
        shape(
            Protocol::Trojan,
            Security::StandardTls,
            Wrapper::H2,
            Udp::PolicyClosed(Closed::TrojanUnsupportedWrapper),
        ),
        shape(
            Protocol::VlessStandard,
            Security::StandardTls,
            Wrapper::Unsupported,
            Udp::PolicyClosed(Closed::VlessUnsupportedShape),
        ),
        shape(
            Protocol::VmessAead,
            Security::StandardTls,
            Wrapper::Unsupported,
            Udp::PolicyClosed(Closed::VmessUnsupportedShape),
        ),
    ];

    for shape in unsupported {
        assert_eq!(profile_for_shape(shape), None, "{shape:?}");
    }
}

#[test]
fn h2_xhttp_and_vmess_h2_security_boundaries_are_explicit() {
    use PolicyClosedDimension as Closed;
    use SecurityDimension as Security;
    use StreamPacketDimension as Stream;
    use UdpDimension as Udp;
    use WrapperDimension as Wrapper;

    let cases = [
        (
            shape(
                Protocol::VlessStandard,
                Security::StandardTls,
                Wrapper::H2,
                Udp::Vless(Stream::H2Tls),
            ),
            Some(FLOW_STREAM_PACKET_OWNERSHIP),
        ),
        (
            shape(
                Protocol::VlessStandard,
                Security::RealityRustls,
                Wrapper::H2,
                Udp::Vless(Stream::H2Tls),
            ),
            None,
        ),
        (
            shape(
                Protocol::VlessStandard,
                Security::StandardTls,
                Wrapper::XhttpH1,
                Udp::Vless(Stream::XhttpH1),
            ),
            Some(CONFIGURED_HTTP_OWNERSHIP),
        ),
        (
            shape(
                Protocol::VlessStandard,
                Security::StandardTls,
                Wrapper::XhttpH2,
                Udp::Vless(Stream::XhttpH2),
            ),
            Some(CONFIGURED_HTTP_OWNERSHIP),
        ),
        (
            shape(
                Protocol::VlessStandard,
                Security::RealityRustls,
                Wrapper::XhttpH2,
                Udp::Vless(Stream::XhttpH2),
            ),
            Some(CONFIGURED_HTTP_OWNERSHIP),
        ),
        (
            shape(
                Protocol::VlessStandard,
                Security::QuicTls,
                Wrapper::XhttpH3,
                Udp::Vless(Stream::XhttpH3),
            ),
            Some(CONFIGURED_HTTP_OWNERSHIP),
        ),
        (
            shape(
                Protocol::VlessStandard,
                Security::StandardTls,
                Wrapper::XhttpH3,
                Udp::Vless(Stream::XhttpH3),
            ),
            None,
        ),
        (
            shape(
                Protocol::VlessStandard,
                Security::RealityRustls,
                Wrapper::XhttpH1,
                Udp::Vless(Stream::XhttpH1),
            ),
            None,
        ),
        (
            shape(
                Protocol::VlessStandard,
                Security::RealityRustls,
                Wrapper::XhttpH3,
                Udp::Vless(Stream::XhttpH3),
            ),
            None,
        ),
        (
            shape(
                Protocol::VmessAead,
                Security::StandardTls,
                Wrapper::H2,
                Udp::PolicyClosed(Closed::VmessH2),
            ),
            Some(FLOW_STREAM_POLICY_CLOSED_OWNERSHIP),
        ),
        (
            shape(
                Protocol::VmessAead,
                Security::None,
                Wrapper::H2,
                Udp::PolicyClosed(Closed::VmessH2),
            ),
            None,
        ),
    ];

    for (shape, expected) in cases {
        assert_eq!(profile_for_shape(shape), expected, "{shape:?}");
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
