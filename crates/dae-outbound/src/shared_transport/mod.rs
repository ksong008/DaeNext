pub const XHTTP_H3_ALPN: &str = "h3";
pub const XHTTP_H3_KEEPALIVE_SECS: u64 = 5;
pub const XHTTP_H3_HANDSHAKE_IDLE_TIMEOUT_SECS: u64 = 8;

pub mod boring_quic {
    pub use dae_outbound_quic::boring_quic::*;
}
pub use dae_outbound_stream::shared_transport::contract;
#[cfg(any(test, feature = "test-support"))]
pub mod dataplane;
pub mod ech {
    pub use dae_outbound_stream::shared_transport::ech::*;
}
pub mod grpc {
    pub use dae_outbound_stream::grpc::*;
}
pub mod grpc_cache {
    pub use dae_outbound_stream::grpc_cache::*;
}
pub mod grpc_http2 {
    pub use dae_outbound_stream::grpc_http2::*;
}
pub mod http_head {
    pub use dae_outbound_stream::http_head::*;
}
pub mod ir {
    pub use dae_outbound_stream::ir::*;
}
pub mod meek {
    pub use dae_outbound_stream::meek::*;
}
pub mod mldsa65 {
    pub use dae_outbound_stream::shared_transport::mldsa65::*;
}
pub mod mux {
    pub use dae_outbound_stream::mux::*;
}
pub mod quic_congestion {
    pub use dae_outbound_quic::congestion::*;
}
#[cfg(any(test, feature = "test-support"))]
pub mod quic_h3 {
    pub use dae_outbound_quic::quic_h3::*;
}
pub mod reality {
    pub use dae_outbound_stream::shared_transport::reality::*;
}
pub mod reality_aead {
    pub use dae_outbound_stream::shared_transport::reality_aead::*;
}
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
#[cfg(any(test, feature = "test-support"))]
pub mod tls;
pub mod tls_fragment {
    pub use dae_outbound_stream::shared_transport::tls_fragment::*;
}
pub mod system_ca {
    pub use dae_outbound_quic::system_ca::*;
}
pub mod utls_fingerprint {
    pub use dae_outbound_stream::shared_transport::utls_fingerprint::*;
}
pub mod utls_template {
    pub use dae_outbound_stream::shared_transport::utls_template::*;
}
pub mod utls_wire {
    pub use dae_outbound_stream::shared_transport::utls_wire::*;
}
pub mod utls_wire_builder {
    pub use dae_outbound_stream::shared_transport::utls_wire_builder::*;
}
pub mod websocket {
    pub use dae_outbound_stream::websocket::*;
}
pub mod xhttp {
    pub use dae_outbound_stream::xhttp::*;
}
#[cfg(any(test, feature = "test-support"))]
pub mod xhttp_h3;

#[cfg(any(test, feature = "test-support"))]
pub use dae_outbound_quic::quic_h3::{
    QuicH3HarnessOptions, QuicH3HarnessReport, parse_quic_h3_datagram, quic_h3_datagram_exchange,
    quic_h3_datagram_packet,
};
pub use dae_outbound_quic::{QuicCongestionController, QuicCongestionControllerError};
pub use dae_outbound_stream::grpc::*;
pub use dae_outbound_stream::grpc_cache::*;
pub use dae_outbound_stream::grpc_http2::*;
pub use dae_outbound_stream::http_head::{
    http_content_length, http_header_value, read_http_head, read_http_head_with_leftover,
    read_http_message,
};
pub use dae_outbound_stream::meek::*;
pub use dae_outbound_stream::mux::*;
pub use dae_outbound_stream::shared_transport::ech::*;
pub use dae_outbound_stream::shared_transport::mldsa65::*;
pub use dae_outbound_stream::shared_transport::reality::*;
pub use dae_outbound_stream::shared_transport::reality_aead::*;
pub use dae_outbound_stream::shared_transport::tls_fragment::*;
pub use dae_outbound_stream::shared_transport::utls_fingerprint::*;
pub use dae_outbound_stream::shared_transport::utls_template::*;
pub use dae_outbound_stream::shared_transport::utls_wire::*;
pub use dae_outbound_stream::shared_transport::utls_wire_builder::*;
pub use dae_outbound_stream::websocket::{
    DEFAULT_WS_KEY, HttpUpgradeOptions, SimpleObfsHttpOptions, WS_ACCEPT_SAMPLE, WS_MASK_KEY,
    WebSocketClientHandshake, http_upgrade_request, read_websocket_binary_frame,
    simpleobfs_http_request, validate_http_status, validate_websocket_handshake_response,
    websocket_accept_for_key, websocket_client_binary_frame,
    websocket_client_binary_frame_with_random_mask, websocket_client_handshake,
    websocket_client_handshake_key, websocket_client_handshake_request, websocket_client_mask_key,
    websocket_handshake_request, websocket_server_binary_frame,
};
pub use dae_outbound_stream::xhttp::*;
#[cfg(any(test, feature = "test-support"))]
pub use dataplane::{
    SharedTransportLoopbackReport, http_upgrade_exchange, simpleobfs_http_exchange,
    websocket_exchange,
};
#[cfg(any(test, feature = "test-support"))]
pub use tls::{
    DEFAULT_TLS_ALPN, DEFAULT_TLS_SERVER_NAME, TlsLoopbackMaterial, TlsServerObservation,
    TlsUnderlayOptions, TlsUnderlayReport, tls_client_echo_exchange, tls_loopback_material,
    tls_server_echo,
};
#[cfg(any(test, feature = "test-support"))]
pub use xhttp_h3::{XHttpH3LoopbackOptions, XHttpH3LoopbackReport, xhttp_h3_packet_up_loopback};
