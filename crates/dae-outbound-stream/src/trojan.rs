pub mod dataplane;
pub mod grpc_dataplane;
pub mod grpc_http2_dataplane;
pub mod inner_shadowsocks_dataplane;

pub use dae_outbound_core::trojan::{metadata, packet};
pub use dataplane::{
    PASSWORD_SHA224_HEX_LEN, TrojanRequestHeader, TrojanTcpExchangeReport, TrojanTcpRequest,
    TrojanUdpOverTcpExchangeReport, TrojanUdpPacket, TrojanUdpPacketPayload, decode_udp_packet,
    decode_udp_packet_payload_prefix, decode_udp_packet_prefix, read_request_header_from_stream,
    read_tcp_request_from_stream, read_udp_packet_from_stream, tcp_exchange_over_stream,
    udp_over_tcp_exchange_over_stream,
};
pub use grpc_dataplane::{
    TROJAN_GRPC_DEFAULT_SERVICE_NAME, TrojanGrpcRequest, TrojanGrpcTcpExchangeReport,
    read_tcp_request_from_grpc_hunk_stream, tcp_exchange_over_grpc_hunk_stream,
    trojan_grpc_service_name,
};
pub use grpc_http2_dataplane::{
    TrojanGrpcHttp2Request, TrojanGrpcHttp2TlsExchangeReport,
    read_tcp_request_from_grpc_http2_stream, tcp_exchange_over_grpc_http2_stream,
    write_grpc_http2_hunk_response,
};
pub use inner_shadowsocks_dataplane::{
    TrojanGoInnerShadowsocksRequest, TrojanGoInnerShadowsocksTcpExchangeReport,
    encode_inner_shadowsocks_response, read_inner_shadowsocks_trojan_request_from_stream,
    tcp_exchange_over_inner_shadowsocks_stream,
};
