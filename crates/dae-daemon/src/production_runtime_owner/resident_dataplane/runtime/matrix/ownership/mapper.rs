use dae_outbound::{
    CONFIGURED_HTTP_OWNERSHIP, FLOW_STREAM_ASSOCIATION_OWNERSHIP, FLOW_STREAM_PACKET_OWNERSHIP,
    FLOW_STREAM_POLICY_CLOSED_OWNERSHIP, GENERATION_OWNED_HYSTERIA2_OWNERSHIP,
    GENERATION_OWNED_JUICITY_OWNERSHIP, GENERATION_OWNED_MEEK_OWNERSHIP,
    GENERATION_OWNED_TUIC_OWNERSHIP, GENERATION_OWNED_VLESS_MUX_OWNERSHIP,
    MATERIALIZED_SHAPE_REJECTED_OWNERSHIP, RuntimeOwnershipProfile,
};

use super::*;
use plan::ResidentProtocolShape as Protocol;

#[path = "mapper/dimensions.rs"]
mod dimensions;
use self::dimensions::*;

#[cfg(test)]
#[path = "mapper/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "mapper/boundary_tests.rs"]
mod boundary_tests;

#[cfg(test)]
#[path = "mapper/security_tests.rs"]
mod security_tests;

// Wildcard tuple arms below are rejection sinks over these local dimensions.
// The source plan enums are converted exhaustively in `dimensions`, so adding a
// protocol, security, wrapper, UDP factory, or stream packet transport cannot
// silently inherit an existing ownership profile.

const STANDARD_TLS_SECURITY: &[SecurityDimension] = &[
    SecurityDimension::StandardTls,
    SecurityDimension::InsecureTls,
    SecurityDimension::FragmentedTls,
    SecurityDimension::FingerprintAwareTls,
];
const TLS_WITHOUT_FINGERPRINT: &[SecurityDimension] = &[
    SecurityDimension::StandardTls,
    SecurityDimension::InsecureTls,
    SecurityDimension::FragmentedTls,
];
const STANDARD_OR_REALITY_SECURITY: &[SecurityDimension] = &[
    SecurityDimension::StandardTls,
    SecurityDimension::InsecureTls,
    SecurityDimension::FragmentedTls,
    SecurityDimension::FingerprintAwareTls,
    SecurityDimension::RealityRustls,
    SecurityDimension::RealityFingerprint,
];

pub(super) fn materialized_execution_shape(
    execution: plan::ResidentExecutionPlan,
) -> dae_outbound::MaterializedExecutionShape {
    project_materialized_execution_shape(execution)
}

pub(super) fn materialized_runtime_ownership(
    execution: plan::ResidentExecutionPlan,
) -> RuntimeOwnershipProfile {
    materialized_runtime_ownership_result(execution)
        .unwrap_or(MATERIALIZED_SHAPE_REJECTED_OWNERSHIP)
}

fn materialized_runtime_ownership_result(
    execution: plan::ResidentExecutionPlan,
) -> Result<RuntimeOwnershipProfile, TypedOwnershipShape> {
    let shape = TypedOwnershipShape::from_execution(execution);
    profile_for_shape(shape).ok_or(shape)
}

fn profile_for_shape(shape: TypedOwnershipShape) -> Option<RuntimeOwnershipProfile> {
    match shape.protocol {
        Protocol::VlessStandard => vless_standard_profile(shape),
        Protocol::VlessVision => exact_profile(
            shape,
            STANDARD_OR_REALITY_SECURITY,
            WrapperDimension::None,
            UdpDimension::VlessVision,
            FLOW_STREAM_PACKET_OWNERSHIP,
        ),
        Protocol::VlessMux => exact_profile(
            shape,
            STANDARD_TLS_SECURITY,
            WrapperDimension::Mux,
            UdpDimension::PolicyClosed(PolicyClosedDimension::VlessMux),
            GENERATION_OWNED_VLESS_MUX_OWNERSHIP,
        ),
        Protocol::Socks5 => exact_profile(
            shape,
            &[SecurityDimension::None],
            WrapperDimension::None,
            UdpDimension::Socks5Associate,
            FLOW_STREAM_ASSOCIATION_OWNERSHIP,
        ),
        Protocol::HttpProxy => http_proxy_profile(shape),
        Protocol::ShadowsocksAead => exact_profile(
            shape,
            &[SecurityDimension::Aead],
            WrapperDimension::None,
            UdpDimension::ShadowsocksAead,
            FLOW_STREAM_PACKET_OWNERSHIP,
        ),
        Protocol::Shadowsocks2022 => exact_profile(
            shape,
            &[SecurityDimension::Aead2022],
            WrapperDimension::None,
            UdpDimension::Shadowsocks2022,
            FLOW_STREAM_PACKET_OWNERSHIP,
        ),
        Protocol::ShadowsocksSimpleObfsHttp => exact_profile(
            shape,
            &[SecurityDimension::Aead],
            WrapperDimension::SimpleObfsHttp,
            UdpDimension::PolicyClosed(PolicyClosedDimension::PluginWrapper),
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
        ),
        Protocol::ShadowsocksSimpleObfsTls => exact_profile(
            shape,
            &[SecurityDimension::Aead],
            WrapperDimension::SimpleObfsTls,
            UdpDimension::PolicyClosed(PolicyClosedDimension::PluginWrapper),
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
        ),
        Protocol::ShadowsocksV2rayPluginTlsWebSocket => exact_profile(
            shape,
            &[
                SecurityDimension::StandardTls,
                SecurityDimension::FragmentedTls,
            ],
            WrapperDimension::V2rayPluginTlsWebSocket,
            UdpDimension::PolicyClosed(PolicyClosedDimension::PluginWrapper),
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
        ),
        Protocol::Shadowsocks2022SimpleObfsHttp => exact_profile(
            shape,
            &[SecurityDimension::Aead2022],
            WrapperDimension::SimpleObfsHttp,
            UdpDimension::PolicyClosed(PolicyClosedDimension::PluginWrapper),
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
        ),
        Protocol::ShadowsocksRHttpSimple => exact_profile(
            shape,
            &[SecurityDimension::LegacyCipher],
            WrapperDimension::LegacyObfs,
            UdpDimension::PolicyClosed(PolicyClosedDimension::ShadowsocksR),
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
        ),
        Protocol::Trojan => trojan_profile(shape),
        Protocol::TrojanInnerShadowsocks => exact_profile(
            shape,
            TLS_WITHOUT_FINGERPRINT,
            WrapperDimension::WebSocket,
            UdpDimension::PolicyClosed(PolicyClosedDimension::TrojanInnerShadowsocks),
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
        ),
        Protocol::AnyTls => exact_profile(
            shape,
            TLS_WITHOUT_FINGERPRINT,
            WrapperDimension::FrameStream,
            UdpDimension::AnyTls,
            FLOW_STREAM_PACKET_OWNERSHIP,
        ),
        Protocol::VmessAead => vmess_profile(shape),
        Protocol::Hysteria2 => exact_profile(
            shape,
            &[SecurityDimension::QuicTls],
            WrapperDimension::QuicStream,
            UdpDimension::Hysteria2,
            GENERATION_OWNED_HYSTERIA2_OWNERSHIP,
        ),
        Protocol::Tuic => exact_profile(
            shape,
            &[SecurityDimension::QuicTls],
            WrapperDimension::QuicStream,
            UdpDimension::Tuic,
            GENERATION_OWNED_TUIC_OWNERSHIP,
        ),
        Protocol::Juicity => exact_profile(
            shape,
            &[SecurityDimension::QuicTls],
            WrapperDimension::QuicStream,
            UdpDimension::Juicity,
            GENERATION_OWNED_JUICITY_OWNERSHIP,
        ),
    }
}

fn vless_standard_profile(shape: TypedOwnershipShape) -> Option<RuntimeOwnershipProfile> {
    use SecurityDimension::None as NoSecurity;
    use StreamPacketDimension as Stream;
    use UdpDimension::Vless;
    use WrapperDimension as Wrapper;

    match (shape.security, shape.wrapper, shape.udp) {
        (NoSecurity, Wrapper::None, Vless(Stream::PlainTcp)) => Some(FLOW_STREAM_PACKET_OWNERSHIP),
        (security, Wrapper::None, Vless(Stream::TlsTcp))
        | (security, Wrapper::WebSocket, Vless(Stream::WebSocketTls))
        | (security, Wrapper::HttpUpgrade, Vless(Stream::HttpUpgradeTls))
        | (security, Wrapper::Grpc, Vless(Stream::GrpcTls))
            if is_standard_or_reality_security(security) =>
        {
            Some(FLOW_STREAM_PACKET_OWNERSHIP)
        }
        (security, Wrapper::H2, Vless(Stream::H2Tls)) if is_standard_tls_security(security) => {
            Some(FLOW_STREAM_PACKET_OWNERSHIP)
        }
        (security, Wrapper::XhttpH1, Vless(Stream::XhttpH1))
            if is_standard_tls_security(security) =>
        {
            Some(CONFIGURED_HTTP_OWNERSHIP)
        }
        (SecurityDimension::QuicTls, Wrapper::XhttpH3, Vless(Stream::XhttpH3)) => {
            Some(CONFIGURED_HTTP_OWNERSHIP)
        }
        (security, Wrapper::XhttpH2, Vless(Stream::XhttpH2))
            if is_standard_or_reality_security(security) =>
        {
            Some(CONFIGURED_HTTP_OWNERSHIP)
        }
        (security, Wrapper::Meek, UdpDimension::PolicyClosed(PolicyClosedDimension::VlessMeek))
            if is_standard_or_reality_security(security) =>
        {
            Some(GENERATION_OWNED_MEEK_OWNERSHIP)
        }
        _ => None,
    }
}

fn http_proxy_profile(shape: TypedOwnershipShape) -> Option<RuntimeOwnershipProfile> {
    let security_supported =
        shape.security == SecurityDimension::None || is_standard_tls_security(shape.security);
    let wrapper_supported = matches!(
        shape.wrapper,
        WrapperDimension::None | WrapperDimension::HttpTransport
    );
    (security_supported
        && wrapper_supported
        && shape.udp == UdpDimension::PolicyClosed(PolicyClosedDimension::HttpConnect))
    .then_some(FLOW_STREAM_POLICY_CLOSED_OWNERSHIP)
}

fn trojan_profile(shape: TypedOwnershipShape) -> Option<RuntimeOwnershipProfile> {
    use StreamPacketDimension as Stream;
    use UdpDimension::Trojan;
    use WrapperDimension as Wrapper;

    match (shape.security, shape.wrapper, shape.udp) {
        (security, Wrapper::None, Trojan(Stream::TlsTcp)) if is_standard_tls_security(security) => {
            Some(FLOW_STREAM_PACKET_OWNERSHIP)
        }
        (security, Wrapper::WebSocket, Trojan(Stream::WebSocketTls))
        | (security, Wrapper::HttpUpgrade, Trojan(Stream::HttpUpgradeTls))
        | (security, Wrapper::Grpc, Trojan(Stream::GrpcTls))
            if TLS_WITHOUT_FINGERPRINT.contains(&security) =>
        {
            Some(FLOW_STREAM_PACKET_OWNERSHIP)
        }
        _ => None,
    }
}

fn vmess_profile(shape: TypedOwnershipShape) -> Option<RuntimeOwnershipProfile> {
    use SecurityDimension::None as NoSecurity;
    use StreamPacketDimension as Stream;
    use UdpDimension::Vmess;
    use WrapperDimension as Wrapper;

    match (shape.security, shape.wrapper, shape.udp) {
        (NoSecurity, Wrapper::None, Vmess(Stream::PlainTcp))
        | (NoSecurity, Wrapper::WebSocket, Vmess(Stream::WebSocketPlain))
        | (NoSecurity, Wrapper::HttpUpgrade, Vmess(Stream::HttpUpgradePlain)) => {
            Some(FLOW_STREAM_PACKET_OWNERSHIP)
        }
        (security, Wrapper::None, Vmess(Stream::TlsTcp))
        | (security, Wrapper::WebSocket, Vmess(Stream::WebSocketTls))
        | (security, Wrapper::HttpUpgrade, Vmess(Stream::HttpUpgradeTls))
        | (security, Wrapper::Grpc, Vmess(Stream::GrpcTls))
            if is_standard_tls_security(security) =>
        {
            Some(FLOW_STREAM_PACKET_OWNERSHIP)
        }
        (security, Wrapper::H2, UdpDimension::PolicyClosed(PolicyClosedDimension::VmessH2))
            if is_standard_tls_security(security) =>
        {
            Some(FLOW_STREAM_POLICY_CLOSED_OWNERSHIP)
        }
        _ => None,
    }
}

fn is_standard_tls_security(security: SecurityDimension) -> bool {
    STANDARD_TLS_SECURITY.contains(&security)
}

fn is_standard_or_reality_security(security: SecurityDimension) -> bool {
    STANDARD_OR_REALITY_SECURITY.contains(&security)
}

fn exact_profile(
    shape: TypedOwnershipShape,
    security: &[SecurityDimension],
    wrapper: WrapperDimension,
    udp: UdpDimension,
    profile: RuntimeOwnershipProfile,
) -> Option<RuntimeOwnershipProfile> {
    (security.contains(&shape.security) && shape.wrapper == wrapper && shape.udp == udp)
        .then_some(profile)
}
