pub use dae_outbound_core::trojan::{contract, link, metadata, packet};
pub mod dataplane {
    pub use dae_outbound_stream::trojan::dataplane::*;
}
pub mod grpc_dataplane {
    pub use dae_outbound_stream::trojan::grpc_dataplane::*;
}
pub mod grpc_http2_dataplane {
    pub use dae_outbound_stream::trojan::grpc_http2_dataplane::*;
}
#[cfg(any(test, feature = "test-support"))]
mod httpupgrade_tls_dataplane;
pub mod inner_shadowsocks_dataplane {
    pub use dae_outbound_stream::trojan::inner_shadowsocks_dataplane::*;
}
#[cfg(any(test, feature = "test-support"))]
mod tls_dataplane;
#[cfg(any(test, feature = "test-support"))]
mod websocket_tls_dataplane;
#[cfg(any(test, feature = "test-support"))]
mod wss_inner_shadowsocks_dataplane;

pub use dae_outbound_core::trojan::{
    TrojanLink, TrojanMetadata, TrojanNetwork, TrojanTransportType,
};
pub use dae_outbound_stream::trojan::dataplane::{
    TrojanRequestHeader, TrojanTcpExchangeReport, TrojanTcpRequest, TrojanUdpOverTcpExchangeReport,
    TrojanUdpPacket, TrojanUdpPacketPayload, decode_udp_packet, decode_udp_packet_payload_prefix,
    decode_udp_packet_prefix, read_request_header_from_stream, read_tcp_request_from_stream,
    read_udp_packet_from_stream, tcp_exchange_over_stream, udp_over_tcp_exchange_over_stream,
};
pub use dae_outbound_stream::trojan::grpc_dataplane::{
    TROJAN_GRPC_DEFAULT_SERVICE_NAME, TrojanGrpcRequest, TrojanGrpcTcpExchangeReport,
    read_tcp_request_from_grpc_hunk_stream, tcp_exchange_over_grpc_hunk_stream,
    trojan_grpc_service_name,
};
pub use dae_outbound_stream::trojan::grpc_http2_dataplane::{
    TrojanGrpcHttp2Request, TrojanGrpcHttp2TlsExchangeReport,
    read_tcp_request_from_grpc_http2_stream, tcp_exchange_over_grpc_http2_stream,
    write_grpc_http2_hunk_response,
};
pub use dae_outbound_stream::trojan::inner_shadowsocks_dataplane::{
    TrojanGoInnerShadowsocksRequest, TrojanGoInnerShadowsocksTcpExchangeReport,
    encode_inner_shadowsocks_response, read_inner_shadowsocks_trojan_request_from_stream,
    tcp_exchange_over_inner_shadowsocks_stream,
};
#[cfg(any(test, feature = "test-support"))]
pub use httpupgrade_tls_dataplane::{
    TrojanGoHttpUpgradeTcpExchangeReport, tcp_exchange_over_httpupgrade_tls_stream,
};
#[cfg(any(test, feature = "test-support"))]
pub use tls_dataplane::{TrojanTlsTcpExchangeReport, tcp_exchange_over_tls_stream};
#[cfg(any(test, feature = "test-support"))]
pub use websocket_tls_dataplane::{
    TrojanGoWssTcpExchangeReport, TrojanWebSocketRequest, read_tcp_request_from_websocket_stream,
    tcp_exchange_over_wss_stream,
};
#[cfg(any(test, feature = "test-support"))]
pub use wss_inner_shadowsocks_dataplane::{
    TrojanGoWssInnerShadowsocksTcpExchangeReport,
    read_inner_shadowsocks_trojan_request_from_websocket_stream,
    tcp_exchange_over_wss_inner_shadowsocks_stream, trojan_wss_inner_shadowsocks_request_frame,
    trojan_wss_inner_shadowsocks_response_frame,
};
