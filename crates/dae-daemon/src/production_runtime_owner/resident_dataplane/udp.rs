use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use super::SharedResidentStopSignal;

use bytes::Bytes;
use dae_datapath::TcpDialMode;
use dae_ebpf_support::open_transparent_udp_socket_bound_in_netns;
use dae_outbound::{
    anytls::{contract as anytls_contract, link as anytls_link},
    hysteria2::{Hysteria2AuthenticatedSession, authenticate_hysteria2_connection},
    juicity::{
        authenticate_juicity_connection, decode_stream_packet_frame, seal_stream_packet_frame,
    },
    shadowsocks::{
        Ss2022UdpCodec, decode_udp_packet as decode_shadowsocks_udp_packet, encode_udp_packet,
        ss2022_udp_unix_timestamp_now,
    },
    shared_transport::{
        HttpUpgradeOptions, http_upgrade_request, validate_http_status,
        websocket_client_binary_frame_with_random_mask, websocket_client_handshake_request,
    },
    socks5::{Socks5Address, udp_packet},
    trojan::packet as trojan_packet,
    tuic::authenticate_tuic_connection,
    vless::packet,
    vmess,
};
use dae_routing::RoutingMatcher;
use serde_json::json;
use tokio::time;

use super::super::PRODUCTION_NETNS;
#[cfg(test)]
use super::super::udp_io::UdpOriginalDstRecvError;
use super::super::udp_io::{
    UDP_RECV_DEFAULT_CAPACITY, UdpOriginalDstPacket, UdpPayloadPool,
    try_recv_udp_with_original_dst_from_pool,
};
use super::client::{
    AsyncResidentTlsClient, async_resident_tls_underlay_name, open_async_resident_tls_client,
    open_proxy_tcp_stream_async,
};
use super::dns::{
    ResidentDnsPlan, build_dns_server_failure_response, handle_resident_dns_udp_async,
};
use super::events::append_event;
use super::execution::{append_runtime_execution_descriptor, udp_execution_descriptor};
#[cfg(test)]
use super::plan::share_resident_proxy_groups;
use super::plan::{
    ResidentHysteria2ObfsPlan, ResidentProtocolShape, ResidentProxyGroupPlan, ResidentProxyPlan,
    ResidentProxyProtocolPlan, ResidentStreamPacketTransport, ResidentUdpExecutorFactory,
    ResidentXhttpHttpVersion, ResidentXhttpMode, SharedResidentProxyGroupMap, UdpPacketSemantics,
    resident_udp_chain_admission,
};
use super::tcp::{
    AsyncWebSocketPayloadReader, AsyncWebSocketPayloadState, GrpcH2Response, GrpcHunkReadBuffer,
    ResidentConnectedQuicEndpoint, XhttpDownloadClient, XhttpPacketUpParts, XhttpStreamParts,
    XhttpStreamUploadClient, XhttpUploadClient, close_xhttp_download_client,
    close_xhttp_stream_upload_client, close_xhttp_upload_client, collect_vmess_grpc_decrypted,
    decode_vmess_grpc_response_stream_async, httpupgrade_handshake_over_resident_tls_async,
    open_grpc_h2_stream, open_h2_body_stream, open_hysteria2_quic_connection_candidates_async,
    open_juicity_quic_connection_candidates_async, open_tuic_quic_connection_candidates_async,
    open_xhttp_packet_up_parts, open_xhttp_stream_parts, poll_xhttp_download_data,
    read_xhttp_download_data, send_grpc_hunk, send_h2_data, send_h2_data_with_context,
    send_xhttp_packet_up_request, send_xhttp_stream_data, set_socket_mark,
    websocket_handshake_over_resident_tls_async,
    write_websocket_binary_frame_over_resident_tls_async,
};
use super::vision::{VisionUnpadder, vision_padding_block};
use super::{
    RESIDENT_IDLE_SLEEP, RESIDENT_UDP_DNS_SESSION_IDLE_TIMEOUT, RESIDENT_UDP_RESPONSE_TIMEOUT,
    RESIDENT_UDP_SESSION_IDLE_TIMEOUT, ResidentDataplaneMetrics, ResidentHealthResuscitationHandle,
    ResidentUdpRuntimeConfig, VISION_COMMAND_CONTINUE, VLESS_RESPONSE_VERSION, XUDP_COMMAND_KEEP,
    XUDP_COMMAND_NEW, XUDP_MUX_TARGET, XUDP_NETWORK_UDP, XUDP_OPTION_DATA,
    apply_resident_udp_socket_buffer_tuning, resident_socket_addr_display,
    resident_udp_network_name,
};

mod worker;
pub(super) use self::worker::*;
mod session_key;
use self::session_key::*;
mod manager;
use self::manager::*;
mod session_actor;
use self::session_actor::*;
mod direct_session;
use self::direct_session::*;
mod session_executor;
use self::session_executor::*;
mod vmess_session;
use self::vmess_session::*;
mod packet_handler;
use self::packet_handler::*;
mod proxy_dns_forwarder;
pub(super) use self::proxy_dns_forwarder::*;
mod probe_dns;
pub(super) use self::probe_dns::*;
mod descriptors;
pub(in crate::production_runtime_owner::resident_dataplane) use self::descriptors::resident_udp_proxy_handler_name;
use self::descriptors::*;
mod stream_helpers;
use self::stream_helpers::*;
mod stream_read;
use self::stream_read::*;
mod quic_helpers;
use self::quic_helpers::*;
mod vless_xudp;
use self::vless_xudp::*;
mod reply;
use self::reply::*;
use self::reply::{UdpReplyDispatcher, UdpReplyHandle};
#[cfg(test)]
#[path = "udp/tests/chain_execution.rs"]
mod chain_execution_tests;
#[cfg(test)]
mod tests;
