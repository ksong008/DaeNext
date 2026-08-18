#![recursion_limit = "256"]

use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, atomic::Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use dae_resident_core::events::{
    ResidentEventKind, ResidentEventMetadata, append_event_with_metadata,
};
pub use dae_resident_core::*;
pub use dae_resident_plan::*;
pub use dae_resident_transport::*;

use bytes::Bytes;
#[cfg(test)]
use dae_core_types::OutboundIndex;
use dae_datapath::TcpDirectDialReport;
#[cfg(test)]
use dae_datapath::{OUTBOUND_BLOCK, OUTBOUND_DIRECT};
use dae_ebpf_support::BpfRoutingResult;
use dae_outbound::{
    http_proxy::{HttpConnectOptions, request as http_request},
    hysteria2::{read_hysteria2_tcp_response, write_hysteria2_tcp_request},
    juicity::write_juicity_tcp_request,
    shadowsocks::{
        AeadStreamCodec, AeadStreamFrameReader, SHADOWSOCKS_AEAD_TCP_BATCH_UPLOAD_BUFFER_SIZE,
        SHADOWSOCKS_AEAD_TCP_DOWNLOAD_BUFFER_SIZE, SHADOWSOCKS_AEAD_TCP_UPLOAD_BUFFER_SIZE,
        SS2022_TCP_RELAY_PAYLOAD_SIZE, SS2022_TCP_RELAY_UPLOAD_BUFFER_SIZE, ShadowsocksMetadata,
        ShadowsocksRStreamDecoder, ShadowsocksRStreamEncoder, Sip003SimpleObfsHttpOptions,
        Sip003SimpleObfsTlsOptions, Ss2022TcpClientStreamEncoder, Ss2022TcpServerStreamDecoder,
        cipher_spec, read_encrypted_chunk_in_place_from_async_stream,
        shadowsocksr_http_simple_origin_request, simple_obfs_http_request_with_body,
        simple_obfs_tls_client_hello_with_body, ss2022_tcp_client_stream_encoder,
        ss2022_tcp_server_stream_decoder_async, ss2022_tcp_unix_timestamp_now,
    },
    shared_transport::mux::MuxFrameOptions,
    shared_transport::{
        HttpUpgradeOptions, MUX_DATA_FRAME_HEADER_BYTES, MeekRoundTripOptions, meek_http_request,
        mux_data_frame, mux_data_frame_header, mux_end_frame, mux_new_frame, validate_http_status,
    },
    trojan::packet as trojan_packet,
    tuic::write_tuic_connect_request,
    vless::packet,
    vless::{VlessEncryptedStream, contract::is_xtls_rprx_vision_flow},
    vmess::{
        VMESS_AEAD_TCP_MAX_PAYLOAD_SIZE, VMESS_AEAD_TCP_UPLOAD_BUFFER_SIZE,
        VMessAeadTcpClientSessionStart, aead_tcp_response_reader_from_buffer,
    },
};
use dae_sniffing::{SniffingError, sniff_tcp};
use serde_json::{Value, json};

#[cfg(test)]
use dae_outbound::vmess::aead_tcp_client_session_start;

mod direct;
pub use self::direct::{
    DirectTcpConnection, DirectTcpRelayStats, open_direct_tcp_connection_async,
    relay_tcp_direct_async,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};
use tokio::time;

mod ports;
pub use ports::*;
mod connection;
pub use connection::handle_tcp_connection_async_or_handoff;

mod shadowsocks_stream;
use shadowsocks_stream::{
    AsyncV2rayPluginMuxPayloadState, ShadowsocksAeadResponseParameters,
    read_shadowsocks_aead_chunk_in_place_from_v2ray_plugin_mux,
    read_shadowsocks_aead_chunk_in_place_from_websocket_tls,
};
mod dns_fast_path;
pub use self::dns_fast_path::*;
mod proxy_fetch;
pub use self::proxy_fetch::*;
mod duplex_relay;
pub use self::duplex_relay::*;
mod executor;
pub use self::executor::*;
mod vless_handlers;
pub use self::vless_handlers::handle_proxy_tcp_connection_async;
mod proxy_dispatch;
pub use self::proxy_dispatch::*;
pub use self::proxy_dispatch::{
    ObservedQuicEndpoint, QuicEndpointCallerClass, QuicEndpointIdentityRole, QuicEndpointProtocol,
    inherit_quic_endpoint_observation, quic_endpoint_metrics_snapshot,
    scope_quic_endpoint_observation,
};
mod plain_handlers;
pub use self::plain_handlers::http_proxy_connect_async;
use self::plain_handlers::*;
mod vmess_handlers;
use self::vmess_handlers::*;
mod transport_helpers;
mod xhttp_relay;
#[cfg(test)]
pub use self::transport_helpers::shutdown_xhttp_xmux_generation_owner;
pub use self::transport_helpers::*;
pub use self::transport_helpers::{
    GrpcH2Response, GrpcHunkReadBuffer, SpawnedLogicalStream, XhttpDownloadClient,
    XhttpPacketUpParts, XhttpPacketUpPipeline, XhttpStreamParts, XhttpStreamUploadClient,
    XhttpUploadClient, XhttpXmuxClearReport, XhttpXmuxGenerationOwnerHandle,
    close_xhttp_download_client, close_xhttp_stream_upload_client, close_xhttp_upload_client,
    open_grpc_h2_stream, open_h2_body_stream, open_h2_body_stream_with_deferred_response,
    open_xhttp_packet_up_parts, open_xhttp_stream_parts, poll_xhttp_download_data,
    read_xhttp_download_data, relay_tcp_over_deferred_h2_body, relay_tcp_over_grpc_h2,
    relay_tcp_over_resident_tls_plain_async, relay_tcp_over_vmess_grpc_h2,
    relay_tcp_over_vmess_h2_body, send_grpc_data, send_grpc_hunk, send_h2_data_with_context,
    send_xhttp_packet_up_request, send_xhttp_stream_data, spawn_grpc_h2_payload_stream,
    spawn_xhttp_packet_up_payload_stream, spawn_xhttp_stream_payload_stream,
    start_xhttp_xmux_generation_owner_on, stop_xhttp_xmux_generation_owner,
};
pub use self::xhttp_relay::{relay_tcp_over_xhttp_packet_up, relay_tcp_over_xhttp_stream};
mod stream_helpers;
pub use self::stream_helpers::open_plain_proxy_tcp_stream_async;
pub use self::stream_helpers::*;
mod shadowsocks_relay;
pub use self::shadowsocks_relay::{
    relay_tcp_over_shadowsocks_2022_async, relay_tcp_over_shadowsocks_2022_simple_obfs_http_async,
    relay_tcp_over_shadowsocks_aead_async, relay_tcp_over_shadowsocks_simple_obfs_http_async,
    relay_tcp_over_shadowsocks_simple_obfs_tls_async,
};
mod shadowsocksr_relay;
pub use self::shadowsocksr_relay::relay_tcp_shadowsocksr_stream_async;
pub use self::shadowsocksr_relay::*;
pub use self::stream_helpers::{
    read_http_head_and_leftover_from_async_stream, validate_simple_obfs_http_response_status,
};
mod vmess_relay;
pub use self::vmess_relay::*;
pub use self::vmess_relay::{
    relay_tcp_over_shadowsocks_v2ray_plugin_tls_ws,
    relay_tcp_over_trojan_websocket_inner_shadowsocks_tls, relay_tcp_over_vmess_aead_async,
    relay_tcp_over_vmess_tls_aead_async, relay_tcp_over_vmess_websocket_aead_async,
    relay_tcp_over_vmess_websocket_tls_aead_async,
};
mod event_builders;
pub use self::event_builders::*;
mod direct_sniffing;
pub use self::direct_sniffing::*;
mod vless_relay;
pub use self::vless_handlers::meek_round_trip_async;
pub use self::vless_relay::relay_tcp_over_trojan_websocket_tls_async;
pub use self::vless_relay::*;
pub use self::vless_relay::{
    relay_tcp_over_vless_tls_async, relay_tcp_over_vless_vision_duplex,
    relay_tcp_over_vless_websocket_tls_async,
};
