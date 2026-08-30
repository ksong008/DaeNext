pub mod anytls;
pub mod grpc;
pub mod grpc_cache;
pub mod grpc_http2;
pub mod hpack;
pub mod hpack_decode;
pub mod http_head;
pub mod http_proxy;
pub mod ir;
pub mod link_identity;
pub mod link_parser;
pub mod meek;
pub mod mux;
pub mod shadowsocks;
pub mod shared_transport;
pub mod socks5;
pub mod trojan;
pub mod vless;
pub mod vmess;
pub mod websocket;
pub mod xhttp;

pub const MAX_HTTP_MESSAGE_BODY_BYTES: usize = 1024 * 1024;

pub fn bounded_http_message_body_length(
    length: usize,
    context: &str,
) -> Result<usize, dae_outbound_core::error::OutboundError> {
    if length > MAX_HTTP_MESSAGE_BODY_BYTES {
        return Err(dae_outbound_core::error::OutboundError::BadSharedTransport(
            format!("{context} body too large: {length} bytes (max {MAX_HTTP_MESSAGE_BODY_BYTES}"),
        ));
    }
    Ok(length)
}

pub use anytls::{AnyTLSLink, AnyTlsFrame, AnyTlsPaddingScheme};
pub use dae_outbound_core::OutboundError;
pub use dae_outbound_core::error;
pub use grpc::{
    GRPC_ACCEPT_ENCODING_HEADER, GRPC_CONTENT_TYPE_APPLICATION, GRPC_CONTENT_TYPE_HEADER,
    GRPC_ENCODING_HEADER, GRPC_IDENTITY_ENCODING, GRPC_TE_HEADER, GRPC_TE_TRAILERS,
    GrpcCacheReport, GrpcLifecycleCache, GrpcLifecycleOptions, GrpcLifecycleReport, GrpcMode,
    grpc_data_frame, grpc_hunk_exchange, grpc_hunk_frame, grpc_hunk_frame_len, grpc_hunk_message,
    grpc_hunk_payload, grpc_hunk_payload_ref, grpc_multi_hunk_frame, grpc_multi_hunk_payloads,
    grpc_request_path, grpc_stream_preface, read_grpc_hunk_frame,
};
pub use grpc_cache::{
    GrpcCacheCancellationStressReport, GrpcDetachedStreamCancellationReport,
    grpc_cache_cleanup_cancellation_stress,
};
pub use grpc_http2::{
    GrpcHttp2FrameReport, GrpcHttp2LifecycleOptions, GrpcHttp2Request, HTTP2_CLIENT_PREFACE,
    HTTP2_FLAG_ACK, HTTP2_FLAG_END_HEADERS, HTTP2_FRAME_DATA, HTTP2_FRAME_HEADERS,
    HTTP2_FRAME_SETTINGS, grpc_hunk_http2_data, http2_frame, read_grpc_http2_request,
    read_grpc_http2_response, read_http2_frame, write_grpc_http2_request,
    write_grpc_http2_response,
};
pub use http_head::{http_content_length, http_header_value, read_http_message};
pub use link_identity::canonical_link_without_display_name;
pub use meek::{
    MeekRoundTripOptions, MeekRoundTripReport, meek_http_request, meek_polling_exchange,
};
pub use shadowsocks::ssr_dataplane::{
    ShadowsocksRThreeLayerExchangeReport, ShadowsocksRThreeLayerOptions,
    ShadowsocksRThreeLayerRequest, encode_shadowsocksr_http_simple_response,
    read_shadowsocksr_http_simple_request, shadowsocksr_three_layer_tcp_exchange_over_stream,
};
pub use shadowsocks::ssr_stream::{
    ShadowsocksRStreamCipherSpec, ShadowsocksRStreamDecoder, ShadowsocksRStreamEncoder,
    shadowsocksr_http_simple_origin_request, shadowsocksr_stream_cipher_specs,
    shadowsocksr_stream_cipher_supported,
};
pub use trojan::{
    PASSWORD_SHA224_HEX_LEN, TROJAN_GRPC_DEFAULT_SERVICE_NAME, TrojanGrpcHttp2Request,
    TrojanGrpcHttp2TlsExchangeReport, TrojanGrpcRequest, TrojanGrpcTcpExchangeReport,
    TrojanRequestHeader, TrojanTcpExchangeReport, TrojanTcpRequest, TrojanUdpOverTcpExchangeReport,
    TrojanUdpPacket, TrojanUdpPacketPayload, decode_udp_packet, decode_udp_packet_payload_prefix,
    decode_udp_packet_prefix, read_request_header_from_stream,
    read_tcp_request_from_grpc_http2_stream, read_tcp_request_from_grpc_hunk_stream,
    read_tcp_request_from_stream, read_udp_packet_from_stream, tcp_exchange_over_grpc_http2_stream,
    tcp_exchange_over_grpc_hunk_stream, tcp_exchange_over_stream, trojan_grpc_service_name,
    udp_over_tcp_exchange_over_stream, write_grpc_http2_hunk_response,
};
pub use vless::{VLESS_VERSION, VLESSLink};
pub use vmess::{VMessLink, VMessSourceFormat};
pub use xhttp::{
    XHttpHttp2FrameReport, XHttpHttp2Request, XHttpLifecycleOptions, XHttpLifecycleReport,
    XHttpXmuxOptions, read_xhttp_http2_request, read_xhttp_http2_response,
    write_xhttp_http2_request, write_xhttp_http2_response, xhttp_packet_exchange,
    xhttp_packet_request, xhttp_request_path,
};
