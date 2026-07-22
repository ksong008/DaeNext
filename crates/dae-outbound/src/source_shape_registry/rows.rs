use super::*;

#[path = "rows/protocol_capabilities.rs"]
mod protocol_capabilities;
#[path = "rows/protocol_endpoints.rs"]
mod protocol_endpoints;
#[path = "rows/shared_transport_capabilities.rs"]
mod shared_transport_capabilities;
#[path = "rows/source_rejections.rs"]
mod source_rejections;
#[path = "rows/stream_wrappers.rs"]
mod stream_wrappers;
#[path = "rows/xhttp_capabilities.rs"]
mod xhttp_capabilities;

pub(super) static SOURCE_SHAPE_REGISTRY_ROWS: &[SourceShapeRegistryRow] = &[
    protocol_endpoints::BASELINE_AEAD_CIPHER_ENDPOINT,
    protocol_endpoints::BASELINE_AEAD_2022_CIPHER_ENDPOINT,
    protocol_endpoints::BASELINE_TLS_AUTH_ENDPOINT,
    protocol_endpoints::BASELINE_AEAD_FRAMED_ENDPOINT,
    protocol_endpoints::VLESS_NATIVE_TCP_ENDPOINT,
    protocol_endpoints::BASELINE_TLS_VISION_ENDPOINT,
    protocol_endpoints::BASELINE_QUIC_AUTH_ENDPOINT,
    protocol_endpoints::BASELINE_QUIC_UUID_ENDPOINT,
    protocol_endpoints::BASELINE_QUIC_PASSWORD_ENDPOINT,
    protocol_endpoints::BASELINE_FRAME_STREAM_ENDPOINT,
    protocol_endpoints::BASELINE_CONNECT_ENDPOINT,
    protocol_endpoints::BASELINE_SOCKS_ENDPOINT,
    protocol_endpoints::CONNECT_UDP_H2_ENDPOINT,
    protocol_endpoints::CONNECT_UDP_H3_ENDPOINT,
    stream_wrappers::STREAM_WRAPPER_WEBSOCKET,
    stream_wrappers::PLAIN_WEBSOCKET_FRAMED_ENDPOINT,
    stream_wrappers::STREAM_WRAPPER_GRPC,
    stream_wrappers::PLAIN_GRPC_FRAMED_ENDPOINT,
    stream_wrappers::STREAM_WRAPPER_HTTPUPGRADE,
    stream_wrappers::PLAIN_HTTPUPGRADE_FRAMED_ENDPOINT,
    stream_wrappers::STREAM_WRAPPER_MEEK,
    stream_wrappers::VLESS_MEEK_TLS_STREAM_WRAPPER,
    stream_wrappers::VLESS_MEEK_REALITY_STREAM_WRAPPER,
    stream_wrappers::VLESS_H2_STREAM_WRAPPER,
    stream_wrappers::VMESS_H2_STREAM_WRAPPER,
    stream_wrappers::XHTTP_H1_WRAPPER,
    stream_wrappers::STREAM_WRAPPER_XHTTP,
    stream_wrappers::NESTED_CHAIN_SHAPE,
    stream_wrappers::PLUGIN_WRAPPER_LAYER,
    protocol_capabilities::LEGACY_LAYER_SHAPE,
    protocol_capabilities::QUIC_OPTION_SURFACE,
    protocol_capabilities::SECURE_ENDPOINT_CAPABILITY,
    protocol_capabilities::SECURE_WEBSOCKET_FRAMED_ENDPOINT,
    protocol_capabilities::SECURE_HTTPUPGRADE_FRAMED_ENDPOINT,
    protocol_capabilities::REALITY_SECURITY_UNDERLAY,
    protocol_capabilities::QUIC_PORT_HOPPING_SURFACE,
    protocol_capabilities::VERIFIED_QUIC_SECURITY_UNDERLAY,
    protocol_capabilities::INNER_ENCRYPTION_STREAM_WRAPPER,
    protocol_capabilities::TLS_WEBSOCKET_PLUGIN_WRAPPER,
    protocol_capabilities::OBFS_TLS_PLUGIN_WRAPPER,
    protocol_capabilities::AEAD_2022_PLUGIN_WRAPPER,
    shared_transport_capabilities::PROXY_TRANSPORT_MODE,
    shared_transport_capabilities::INSECURE_SECURE_ENDPOINT_UNDERLAY,
    shared_transport_capabilities::FINGERPRINT_SECURE_ENDPOINT_UNDERLAY,
    shared_transport_capabilities::INSECURE_FRAME_STREAM_UNDERLAY,
    shared_transport_capabilities::FULL_UTLS_SECURITY_UNDERLAY,
    shared_transport_capabilities::TLS_FRAGMENT_SECURITY_UNDERLAY,
    shared_transport_capabilities::SHARED_REALITY_SECURITY_UNDERLAY,
    shared_transport_capabilities::MUX_TRANSPORT_WRAPPER,
    shared_transport_capabilities::PASSTHROUGH_UDP_TRANSPORT,
    shared_transport_capabilities::LEGACY_CIPHER_PROTOCOL_SHAPE,
    xhttp_capabilities::XHTTP_H3_WRAPPER,
    xhttp_capabilities::XHTTP_EXTENDED_SETTINGS_WRAPPER,
    source_rejections::NON_NATIVE_ABI_OUTBOUND_SHAPE,
    source_rejections::EXTERNAL_RUNTIME_DEPENDENT_SHAPE,
    source_rejections::NON_NATIVE_EXECUTOR_DEPENDENT_SHAPE,
];
