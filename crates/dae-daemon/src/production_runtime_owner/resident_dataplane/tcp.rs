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
    Hysteria2OwnerRegistryHandle, ResidentStopSignal, SharedResidentStopSignal,
    reset_resident_relay_idle_deadline, resident_relay_idle_deadline,
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
use dae_outbound::{
    anytls::{AnyTlsFrame, contract as anytls_contract, link as anytls_link},
    http_proxy::{HttpConnectOptions, request as http_request},
    hysteria2::{
        HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD,
        build_hysteria2_runtime_client_config_with_udp_overhead, read_hysteria2_tcp_response,
        write_hysteria2_tcp_request,
    },
    juicity::{
        authenticate_juicity_connection, build_juicity_runtime_client_config,
        write_juicity_tcp_request,
    },
    shadowsocks::{
        AeadStreamCodec, ShadowsocksMetadata, ShadowsocksRStreamDecoder, ShadowsocksRStreamEncoder,
        Sip003SimpleObfsHttpOptions, Sip003SimpleObfsTlsOptions, Ss2022TcpClientStreamEncoder,
        Ss2022TcpServerStreamDecoder, cipher_spec, read_encrypted_chunk_from_async_stream,
        shadowsocksr_http_simple_origin_request, simple_obfs_http_request_with_body,
        simple_obfs_tls_client_hello_with_body, ss2022_tcp_client_stream_encoder,
        ss2022_tcp_server_stream_decoder_async, ss2022_tcp_unix_timestamp_now,
    },
    shared_transport::mux::{
        MuxFrameOptions, OPTION_DATA, SESSION_STATUS_END, SESSION_STATUS_KEEP,
        SESSION_STATUS_KEEPALIVE,
    },
    shared_transport::{
        GRPC_ACCEPT_ENCODING_HEADER, GRPC_CONTENT_TYPE_APPLICATION, GRPC_ENCODING_HEADER,
        GRPC_IDENTITY_ENCODING, GRPC_TE_HEADER, GRPC_TE_TRAILERS, HttpUpgradeOptions,
        MeekRoundTripOptions, grpc_hunk_frame, grpc_hunk_payload, ir, meek_http_request,
        mux_data_frame, mux_end_frame, mux_new_frame, validate_http_status,
    },
    socks5::{Socks5Address, handshake},
    trojan::packet as trojan_packet,
    tuic::{
        authenticate_tuic_connection, build_tuic_runtime_client_config, write_tuic_connect_request,
    },
    vless::contract::is_xtls_rprx_vision_flow,
    vless::packet,
    vmess::{
        VMessAeadTcpClientSessionStart, VMessMetadata, aead_tcp_client_session_start,
        aead_tcp_response_reader_from_async_stream,
    },
};
use dae_routing::{Query, RoutingMatcher};
use dae_sniffing::{SniffingError, sniff_tcp};
use rustls::pki_types::ServerName;
use serde_json::{Value, json};

use super::client::{
    AsyncResidentTlsClient, AsyncVlessTlsClient, async_resident_tls_underlay_name,
    async_tls_underlay_name, open_async_resident_tls_client,
    open_async_resident_tls_client_with_flow, open_async_vless_tls_client_with_flow,
    open_async_vless_tls_client_with_flow_at_candidates, open_async_xhttp_endpoint_tls_client,
    open_async_xhttp_endpoint_tls_client_at_candidates, open_proxy_tcp_stream_async_with_flow,
};
use super::direct::{
    DirectTcpConnection, DirectTcpRelayStats, open_direct_tcp_connection_async,
    relay_tcp_direct_async,
};
use super::dns::{ResidentDnsDomainRouting, ResidentDnsPlan};
use super::events::append_event;
use super::execution::{append_runtime_execution_descriptor, tcp_execution_descriptor};
#[cfg(test)]
use super::plan::ResidentProxyGroupPlan;
#[cfg(test)]
use super::plan::share_resident_proxy_groups;
use super::plan::{
    ResidentHysteria2ObfsPlan, ResidentProtocolShape, ResidentProxyPlan, ResidentProxyProtocolPlan,
    ResidentSecurityUnderlayPlan, ResidentStreamWrapperPlan, ResidentTcpRuntimeDispatch,
    ResidentXhttpEndpointPlan, ResidentXhttpHttpVersion, ResidentXhttpMetaPlacement,
    ResidentXhttpMode, ResidentXhttpPaddingMethod, ResidentXhttpPaddingPlacement,
    ResidentXhttpSettingsPlan, ResidentXhttpUplinkDataPlacement, ResidentXhttpXmuxPlan,
    SharedResidentProxyGroupMap,
};
use super::probe::resident_tcp_probe_tls_config;
#[cfg(test)]
use super::probe::{resident_tcp_probe_http_request, resident_tcp_probe_status_ok};
use super::vision::{
    VisionInnerTlsState, VisionUnpadder, VisionUplinkMode, drain_vision_uplink_async,
};
use super::{
    RESIDENT_CONNECT_TIMEOUT, RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT,
    RESIDENT_TCP_IDLE_TIMEOUT, TLS_RECORD_MAX_PAYLOAD_LEN, VLESS_RESPONSE_VERSION,
    resident_normalized_socket_addr, resident_socket_addr_display, resident_tcp_network_name,
};
use super::{ResidentDataplaneMetrics, ResidentTcpConnectionGuard};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};
use tokio::runtime;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time;

mod shadowsocks_stream;
mod websocket;

pub(in crate::production_runtime_owner::resident_dataplane) use self::websocket::{
    httpupgrade_handshake_over_async_stream as native_httpupgrade_handshake_over_async_stream,
    httpupgrade_handshake_over_resident_tls_async as native_httpupgrade_handshake_over_resident_tls_async,
    websocket_handshake_over_async_stream as native_websocket_handshake_over_async_stream,
    websocket_handshake_over_resident_tls_async as native_websocket_handshake_over_resident_tls_async,
    write_websocket_binary_frame_over_resident_tls_async as native_write_websocket_binary_frame_over_resident_tls_async,
    write_websocket_binary_frame_to_async_stream as native_write_websocket_binary_frame_to_async_stream,
};
use shadowsocks_stream::{
    AsyncV2rayPluginMuxPayloadState, read_shadowsocks_aead_chunk_from_v2ray_plugin_mux,
    read_shadowsocks_aead_chunk_from_websocket_tls,
};
pub(crate) use websocket::{
    AsyncWebSocketPayloadReader, AsyncWebSocketPayloadState, RESIDENT_WEBSOCKET_MAX_MESSAGE_BYTES,
};
use websocket::{
    WebSocketBinaryFrameDecoder, httpupgrade_handshake_over_async_stream,
    websocket_handshake_over_async_stream, write_websocket_binary_frame_to_async_stream,
    write_websocket_control_responses_over_resident_tls_async,
};
pub(in crate::production_runtime_owner::resident_dataplane) use websocket::{
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
use self::admission::*;
mod executor;
pub(super) use self::executor::*;
mod vless_handlers;
use self::vless_handlers::*;
mod proxy_dispatch;
pub(super) use self::proxy_dispatch::*;
pub(in crate::production_runtime_owner::resident_dataplane) use self::proxy_dispatch::{
    ObservedQuicEndpoint, QuicEndpointCallerClass, QuicEndpointIdentityRole,
    QuicEndpointOpenContext, QuicEndpointProtocol, ResidentConnectedQuicEndpoint,
    connect_quic_endpoint_candidates_async, inherit_quic_endpoint_observation,
    open_hysteria2_quic_connection_candidates_async, open_juicity_quic_connection_candidates_async,
    open_marked_quic_endpoint_for_remote, open_tuic_quic_connection_candidates_async,
    quic_endpoint_metrics_snapshot, relay_tcp_over_anytls_async, scope_quic_endpoint_observation,
    wait_anytls_synack, write_anytls_frame,
};
mod plain_handlers;
pub(in crate::production_runtime_owner::resident_dataplane) use self::plain_handlers::http_proxy_connect_async;
use self::plain_handlers::*;
mod vmess_handlers;
use self::vmess_handlers::*;
mod transport_helpers;
use self::transport_helpers::*;
pub(crate) use self::transport_helpers::{
    GrpcH2Response, GrpcHunkReadBuffer, XhttpDownloadClient, XhttpPacketUpParts, XhttpStreamParts,
    XhttpStreamUploadClient, XhttpUploadClient, clear_xhttp_xmux_managers,
    close_xhttp_download_client, close_xhttp_stream_upload_client, close_xhttp_upload_client,
    collect_vmess_grpc_decrypted, decode_vmess_grpc_response_stream_async, open_grpc_h2_stream,
    open_h2_body_stream, open_h2_body_stream_with_deferred_response, open_xhttp_packet_up_parts,
    open_xhttp_stream_parts, poll_xhttp_download_data, read_xhttp_download_data,
    relay_tcp_over_deferred_h2_body, relay_tcp_over_grpc_h2,
    relay_tcp_over_resident_tls_plain_async, relay_tcp_over_vmess_grpc_h2,
    relay_tcp_over_vmess_h2_body, relay_tcp_over_xhttp_packet_up, relay_tcp_over_xhttp_stream,
    send_grpc_hunk, send_h2_data, send_h2_data_with_context, send_xhttp_packet_up_request,
    send_xhttp_stream_data,
};
mod stream_helpers;
use self::stream_helpers::*;
mod http_connect_head;
use self::http_connect_head::*;
pub(in crate::production_runtime_owner::resident_dataplane) use self::stream_helpers::{
    http_proxy_connect_plain_async, open_plain_proxy_tcp_stream_async, socks5_connect_async,
};
mod shadowsocks_relay;
pub(in crate::production_runtime_owner::resident_dataplane) use self::shadowsocks_relay::{
    relay_tcp_over_shadowsocks_2022_async, relay_tcp_over_shadowsocks_2022_simple_obfs_http_async,
    relay_tcp_over_shadowsocks_aead_async, relay_tcp_over_shadowsocks_simple_obfs_http_async,
    relay_tcp_over_shadowsocks_simple_obfs_tls_async,
};
mod shadowsocksr_relay;
pub(in crate::production_runtime_owner::resident_dataplane) use self::shadowsocksr_relay::relay_tcp_shadowsocksr_stream_async;
use self::shadowsocksr_relay::*;
pub(in crate::production_runtime_owner::resident_dataplane) use self::stream_helpers::{
    read_http_head_and_leftover_from_async_stream, validate_simple_obfs_http_response_status,
};
mod vmess_relay;
use self::vmess_relay::*;
pub(in crate::production_runtime_owner::resident_dataplane) use self::vmess_relay::{
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
pub(in crate::production_runtime_owner::resident_dataplane) use self::vless_handlers::{
    meek_round_trip_async, relay_tcp_over_vless_mux_tls_async,
};
pub(in crate::production_runtime_owner::resident_dataplane) use self::vless_relay::relay_tcp_over_trojan_websocket_tls_async;
use self::vless_relay::*;
pub(in crate::production_runtime_owner::resident_dataplane) use self::vless_relay::{
    relay_tcp_over_vless_tls_async, relay_tcp_over_vless_websocket_tls_async,
};
#[cfg(test)]
mod tests;
