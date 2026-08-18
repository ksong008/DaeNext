#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::future::poll_fn;
use std::io::ErrorKind;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::pin::Pin;
use std::slice;
use std::sync::{Arc, Mutex, atomic::Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use super::{
    AnyTlsLogicalStreamLease, AnyTlsOwnerRegistryHandle, H2CarrierLease,
    H2CarrierOwnerResourceProfile, H2CarrierResponseFuture, Hysteria2OwnerRegistryHandle,
    Hysteria2OwnerResourceProfile, JuicityOwnerRegistryHandle, ResidentStopSignal,
    ResidentTaskSetShutdown, ResidentTransportOwnerRegistries, SharedResidentStopSignal,
    TuicOwnerRegistryHandle, acquire_h2_carrier, acquire_meek_transport,
    record_resident_task_completion, reset_resident_relay_idle_deadline,
    resident_relay_idle_deadline, run_until_resident_stop, shutdown_resident_task_set,
};

use bytes::Bytes;
use dae_core_types::OutboundIndex;
use dae_datapath::{
    OUTBOUND_BLOCK, OUTBOUND_CONTROL_PLANE_ROUTING, OUTBOUND_DIRECT, TcpDialMode,
    TcpDirectDialReport, choose_dial_target, outbound_is_reserved,
};
use dae_ebpf_support::{
    BpfIpBytes, BpfRoutingResult, BpfTuplesKey, lookup_map_elem_bytes, open_map_fd,
};
#[cfg(test)]
use dae_outbound::hysteria2::build_hysteria2_runtime_client_config_with_udp_overhead;
use dae_outbound::{
    anytls::{AnyTlsFrame, contract as anytls_contract},
    http_proxy::{HttpConnectOptions, request as http_request},
    hysteria2::{
        HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD, Hysteria2CongestionRuntime,
        build_hysteria2_runtime_client_config_with_session_cache, read_hysteria2_tcp_response,
        write_hysteria2_tcp_request,
    },
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
        GRPC_ACCEPT_ENCODING_HEADER, GRPC_CONTENT_TYPE_APPLICATION, GRPC_ENCODING_HEADER,
        GRPC_IDENTITY_ENCODING, GRPC_TE_HEADER, GRPC_TE_TRAILERS, GrpcMode, HttpUpgradeOptions,
        MUX_DATA_FRAME_HEADER_BYTES, MeekRoundTripOptions, grpc_data_frame, grpc_hunk_payload_ref,
        grpc_multi_hunk_payloads, grpc_request_path as official_grpc_request_path, ir,
        meek_http_request, mux_data_frame, mux_data_frame_header, mux_end_frame, mux_new_frame,
        validate_http_status,
    },
    socks5::{Socks5Address, handshake},
    trojan::packet as trojan_packet,
    tuic::{
        TuicCongestionController, build_tuic_runtime_client_config_with_session_cache,
        write_tuic_connect_request,
    },
    vless::packet,
    vless::{VlessEncryptedStream, contract::is_xtls_rprx_vision_flow},
    vmess::{
        VMESS_AEAD_TCP_MAX_PAYLOAD_SIZE, VMESS_AEAD_TCP_UPLOAD_BUFFER_SIZE,
        VMessAeadTcpClientSessionStart, aead_tcp_response_reader_from_buffer,
    },
};
use dae_routing::{Query, RoutingMatcher};
use dae_sniffing::{SniffingError, sniff_tcp};
use serde_json::{Value, json};

#[cfg(test)]
use dae_outbound::vmess::aead_tcp_client_session_start;

use super::ResidentDnsResolver;
use super::client::{
    AsyncResidentTlsClient, AsyncVlessTlsClient, async_resident_tls_underlay_name,
    async_tls_underlay_name, open_async_resident_tls_client_with_binding,
    open_async_vless_tls_client_with_flow_at_candidates, open_async_xhttp_endpoint_tls_client,
    open_async_xhttp_endpoint_tls_client_at_candidates, open_proxy_tcp_stream_with_binding,
};
use super::direct::{
    DirectTcpConnection, DirectTcpRelayStats, open_direct_tcp_connection_async,
    relay_tcp_direct_async,
};
use super::events::{
    ResidentEventKind, ResidentEventMetadata, append_event, append_event_with_metadata,
};
use super::execution::{append_runtime_execution_descriptor, tcp_execution_descriptor};
#[cfg(test)]
use super::plan::ResidentProxyGroupPlan;
#[cfg(test)]
use super::plan::share_resident_proxy_groups;
use super::plan::{
    ResidentHysteria2ObfsPlan, ResidentProtocolShape, ResidentProxyBinding, ResidentProxyPlan,
    ResidentProxyProtocolPlan, ResidentSecurityUnderlayPlan, ResidentStreamWrapperPlan,
    ResidentTcpRuntimeDispatch, ResidentXhttpEndpointPlan, ResidentXhttpHttpVersion,
    ResidentXhttpMetaPlacement, ResidentXhttpMode, ResidentXhttpPaddingMethod,
    ResidentXhttpPaddingPlacement, ResidentXhttpSettingsPlan, ResidentXhttpUplinkDataPlacement,
    ResidentXhttpXmuxPlan, SharedResidentProxyGroupMap,
};
#[cfg(test)]
use super::probe::{resident_tcp_probe_http_request, resident_tcp_probe_status_ok};
#[cfg(test)]
use super::vision::VisionTlsDecision;
use super::vision::{
    VisionInnerTlsState, VisionUnpadder, VisionUplinkState, VisionUplinkWrite,
    VisionUplinkWriteMode, queue_vision_uplink,
};
use super::{
    CursorBytes, HttpHeadReadError, HttpHeadReadOptions, RESIDENT_ANYTLS_RELAY_BUFFER_SIZE,
    RESIDENT_CONNECT_TIMEOUT, RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT,
    RESIDENT_TCP_IDLE_TIMEOUT, TLS_RECORD_MAX_PAYLOAD_LEN, VLESS_RESPONSE_VERSION, read_http_head,
    resident_normalized_socket_addr, resident_socket_addr_display, resident_tcp_network_name,
};
use super::{ResidentDataplaneMetrics, ResidentTcpConnectionGuard};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time;

mod shadowsocks_stream;
mod vmess_http_header;
mod websocket;

pub(crate) use vmess_http_header::{VmessHttpHeaderStream, open_vmess_http_header_stream};

pub(crate) use self::websocket::{
    httpupgrade_handshake_over_async_stream as native_httpupgrade_handshake_over_async_stream,
    httpupgrade_handshake_over_resident_tls_async as native_httpupgrade_handshake_over_resident_tls_async,
    websocket_handshake_over_async_stream as native_websocket_handshake_over_async_stream,
    websocket_handshake_over_resident_tls_async as native_websocket_handshake_over_resident_tls_async,
    write_websocket_binary_frame_over_resident_tls_async as native_write_websocket_binary_frame_over_resident_tls_async,
    write_websocket_binary_frame_to_async_stream as native_write_websocket_binary_frame_to_async_stream,
};
use shadowsocks_stream::{
    AsyncV2rayPluginMuxPayloadState, ShadowsocksAeadResponseParameters,
    read_shadowsocks_aead_chunk_in_place_from_v2ray_plugin_mux,
    read_shadowsocks_aead_chunk_in_place_from_websocket_tls,
};
pub(crate) use websocket::spawn_websocket_payload_stream;
#[cfg(test)]
pub(crate) use websocket::{AsyncWebSocketPayloadChannelReader, AsyncWebSocketPayloadChannelState};
pub(crate) use websocket::{
    AsyncWebSocketPayloadReader, AsyncWebSocketPayloadState, RESIDENT_WEBSOCKET_MAX_MESSAGE_BYTES,
    RESIDENT_WEBSOCKET_RELAY_BUFFER_SIZE,
};
use websocket::{
    WebSocketBinaryFrameDecoder, httpupgrade_handshake_over_async_stream,
    queue_websocket_control_responses, websocket_control_channel,
    websocket_handshake_over_async_stream, write_websocket_binary_frame_in_place_to_async_stream,
    write_websocket_binary_frame_to_async_stream, write_websocket_control_response,
};
pub(crate) use websocket::{
    httpupgrade_handshake_over_resident_tls_async, websocket_handshake_over_resident_tls_async,
    write_websocket_binary_frame_over_resident_tls_async,
};

mod router;
pub(super) use self::router::*;
mod dns_fast_path;
use self::dns_fast_path::*;
mod proxy_fetch;
pub(super) use self::proxy_fetch::*;
mod accept_loop;
pub(super) use self::accept_loop::*;
mod admission;
pub(crate) use self::admission::ResidentTcpAdmission;
mod duplex_relay;
pub(super) use self::duplex_relay::*;
mod executor;
pub(super) use self::executor::*;
mod vless_handlers;
use self::vless_handlers::*;
mod proxy_dispatch;
pub(super) use self::proxy_dispatch::*;
pub(crate) use self::proxy_dispatch::{
    Hysteria2PortHoppingMetrics, Hysteria2QuicConnectionRequest, ObservedQuicEndpoint,
    QuicEndpointCallerClass, QuicEndpointIdentityRole, QuicEndpointProtocol,
    ResidentConnectedQuicEndpoint, connect_quic_endpoint_candidates_async,
    inherit_quic_endpoint_observation, open_hysteria2_quic_connection_candidates_async,
    open_juicity_quic_connection_candidates_async, open_marked_quic_endpoint_for_remote,
    open_tuic_quic_connection_candidates_async, quic_endpoint_metrics_snapshot,
    scope_quic_endpoint_observation,
};
mod plain_handlers;
pub(crate) use self::plain_handlers::http_proxy_connect_async;
use self::plain_handlers::*;
mod vmess_handlers;
use self::vmess_handlers::*;
mod transport_helpers;
#[cfg(test)]
pub(crate) use self::transport_helpers::shutdown_xhttp_xmux_generation_owner;
use self::transport_helpers::*;
pub(crate) use self::transport_helpers::{
    GrpcH2Response, GrpcHunkReadBuffer, SpawnedLogicalStream, XhttpDownloadClient,
    XhttpPacketUpParts, XhttpPacketUpPipeline, XhttpStreamParts, XhttpStreamUploadClient,
    XhttpUploadClient, XhttpXmuxClearReport, XhttpXmuxGenerationOwnerHandle,
    close_xhttp_download_client, close_xhttp_stream_upload_client, close_xhttp_upload_client,
    open_grpc_h2_stream, open_h2_body_stream, open_h2_body_stream_with_deferred_response,
    open_xhttp_packet_up_parts, open_xhttp_stream_parts, poll_xhttp_download_data,
    read_xhttp_download_data, relay_tcp_over_deferred_h2_body, relay_tcp_over_grpc_h2,
    relay_tcp_over_resident_tls_plain_async, relay_tcp_over_vmess_grpc_h2,
    relay_tcp_over_vmess_h2_body, relay_tcp_over_xhttp_packet_up, relay_tcp_over_xhttp_stream,
    send_grpc_data, send_grpc_hunk, send_h2_data_with_context, send_xhttp_packet_up_request,
    send_xhttp_stream_data, spawn_grpc_h2_payload_stream, spawn_xhttp_packet_up_payload_stream,
    spawn_xhttp_stream_payload_stream, start_xhttp_xmux_generation_owner_on,
    stop_xhttp_xmux_generation_owner,
};
mod stream_helpers;
use self::stream_helpers::*;
mod http_connect_head;
use self::http_connect_head::*;
pub(crate) use self::stream_helpers::{
    http_proxy_connect_plain_async, open_plain_proxy_tcp_stream_async, socks5_connect_async,
};
pub(crate) use super::AsyncPrefixedStream;
mod shadowsocks_relay;
pub(crate) use self::shadowsocks_relay::{
    relay_tcp_over_shadowsocks_2022_async, relay_tcp_over_shadowsocks_2022_simple_obfs_http_async,
    relay_tcp_over_shadowsocks_aead_async, relay_tcp_over_shadowsocks_simple_obfs_http_async,
    relay_tcp_over_shadowsocks_simple_obfs_tls_async,
};
mod shadowsocksr_relay;
pub(crate) use self::shadowsocksr_relay::relay_tcp_shadowsocksr_stream_async;
use self::shadowsocksr_relay::*;
pub(crate) use self::stream_helpers::{
    read_http_head_and_leftover_from_async_stream, validate_simple_obfs_http_response_status,
};
mod vmess_relay;
use self::vmess_relay::*;
pub(crate) use self::vmess_relay::{
    relay_tcp_over_shadowsocks_v2ray_plugin_tls_ws,
    relay_tcp_over_trojan_websocket_inner_shadowsocks_tls, relay_tcp_over_vmess_aead_async,
    relay_tcp_over_vmess_tls_aead_async, relay_tcp_over_vmess_websocket_aead_async,
    relay_tcp_over_vmess_websocket_tls_aead_async,
};
mod event_builders;
use self::event_builders::*;
mod direct_sniffing;
use self::direct_sniffing::*;
mod vless_relay;
pub(crate) use self::vless_handlers::meek_round_trip_async;
pub(crate) use self::vless_relay::relay_tcp_over_trojan_websocket_tls_async;
use self::vless_relay::*;
pub(crate) use self::vless_relay::{
    relay_tcp_over_vless_tls_async, relay_tcp_over_vless_vision_duplex,
    relay_tcp_over_vless_websocket_tls_async,
};
#[cfg(test)]
mod tests;
