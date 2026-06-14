use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dae_ebpf_support::open_transparent_udp_socket_bound_in_netns;
use dae_outbound::{
    anytls::{contract as anytls_contract, link as anytls_link},
    hysteria2::{authenticate_hysteria2_connection, build_hysteria2_pinned_client_config},
    juicity::{
        authenticate_juicity_connection, build_juicity_runtime_client_config,
        decode_stream_packet_frame, seal_stream_packet_frame,
    },
    shadowsocks::{
        Ss2022UdpCodec, decode_udp_packet as decode_shadowsocks_udp_packet, encode_udp_packet,
        ss2022_udp_unix_timestamp_now,
    },
    shared_transport::{
        DEFAULT_WS_KEY, HttpUpgradeOptions, WS_MASK_KEY, http_upgrade_request,
        validate_http_status, websocket_client_binary_frame, websocket_handshake_request,
    },
    socks5::{Socks5Address, udp_packet},
    trojan::{decode_udp_packet as decode_trojan_udp_packet, packet as trojan_packet},
    tuic::{authenticate_tuic_connection, build_tuic_runtime_client_config},
    vless::packet,
    vmess,
};
use serde_json::json;
use tokio::time;

use super::super::PRODUCTION_NETNS;
use super::super::udp_io::{
    UdpOriginalDstPacket, UdpPayloadPool, try_recv_udp_with_original_dst_from_pool,
};
use super::client::{
    AsyncResidentTlsClient, async_resident_tls_underlay_name, open_async_resident_tls_client,
    open_proxy_tcp_stream_async,
};
use super::dns::{ResidentDnsPlan, handle_resident_dns_udp_async};
use super::events::append_event;
use super::execution::{append_runtime_execution_descriptor, udp_execution_descriptor};
use super::plan::{
    ResidentProxyGroupPlan, ResidentProxyPlan, ResidentProxyProtocolPlan, ResidentXhttpHttpVersion,
    ResidentXhttpMode,
};
use super::tcp::{
    AsyncWebSocketPayloadReader, AsyncWebSocketPayloadState, GrpcHunkReadBuffer,
    XhttpDownloadClient, XhttpPacketUpParts, XhttpStreamParts, XhttpStreamUploadClient,
    XhttpUploadClient, close_xhttp_download_client, close_xhttp_stream_upload_client,
    close_xhttp_upload_client, collect_vmess_grpc_decrypted,
    decode_vmess_grpc_response_stream_async, open_grpc_h2_stream, open_marked_quic_endpoint,
    open_xhttp_packet_up_parts, open_xhttp_stream_parts, poll_xhttp_download_data,
    resolve_hysteria2_quic_remote_async, resolve_proxy_udp_addr_async, send_grpc_hunk,
    send_h2_data, send_xhttp_packet_up_request, send_xhttp_stream_data, set_socket_mark,
};
use super::vision::{VisionUnpadder, vision_padding_block};
use super::{
    RESIDENT_IDLE_SLEEP, RESIDENT_UDP_RESPONSE_TIMEOUT, RESIDENT_UDP_SESSION_IDLE_TIMEOUT,
    ResidentDataplaneMetrics, VISION_COMMAND_CONTINUE, VLESS_RESPONSE_VERSION, XTLS_RPRX_VISION,
    XUDP_COMMAND_KEEP, XUDP_COMMAND_NEW, XUDP_MUX_TARGET, XUDP_NETWORK_UDP, XUDP_OPTION_DATA,
    resident_socket_addr_display, resident_udp_network_name,
};

mod worker;
pub(super) use self::worker::*;
mod session_key;
use self::session_key::*;
mod manager;
use self::manager::*;
mod session_actor;
use self::session_actor::*;
mod session_executor;
use self::session_executor::*;
mod vmess_session;
use self::vmess_session::*;
mod packet_handler;
use self::packet_handler::*;
mod probe_dns;
pub(super) use self::probe_dns::*;
mod descriptors;
pub(in crate::production_runtime_owner::resident_dataplane) use self::descriptors::resident_udp_handler_name;
use self::descriptors::*;
mod stream_helpers;
use self::stream_helpers::*;
mod quic_helpers;
use self::quic_helpers::*;
mod vless_xudp;
use self::vless_xudp::*;
mod reply;
use self::reply::*;
#[cfg(test)]
mod tests;

fn resident_xhttp_uses_h3(proxy: &ResidentProxyPlan) -> bool {
    resident_xhttp_primary_http_version(proxy) == ResidentXhttpHttpVersion::H3
}

fn resident_xhttp_primary_http_version(proxy: &ResidentProxyPlan) -> ResidentXhttpHttpVersion {
    if proxy.net != "xhttp" || proxy.tls == "reality" {
        ResidentXhttpHttpVersion::H2
    } else {
        ResidentXhttpHttpVersion::from_tls_alpn(&proxy.alpn)
    }
}
