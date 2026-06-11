use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
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
use super::super::udp_io::{UdpOriginalDstPacket, try_recv_udp_with_original_dst};
use super::client::{
    AsyncResidentTlsClient, async_resident_tls_underlay_name, open_async_resident_tls_client,
    open_proxy_tcp_stream_async,
};
use super::dns::{ResidentDnsPlan, handle_resident_dns_udp_async};
use super::events::append_event;
use super::execution::{append_runtime_execution_descriptor, udp_execution_descriptor};
use super::plan::{ResidentProxyGroupPlan, ResidentProxyPlan, ResidentProxyProtocolPlan};
use super::tcp::{
    AsyncWebSocketPayloadReader, AsyncWebSocketPayloadState, collect_vmess_grpc_decrypted,
    decode_vmess_grpc_response_stream_async, open_grpc_h2_stream, open_marked_quic_endpoint,
    pop_grpc_hunk_payload, resolve_hysteria2_quic_remote_async, resolve_proxy_udp_addr_async,
    send_grpc_hunk, send_h2_data, set_socket_mark,
};
use super::vision::{VisionUnpadState, VisionUnpadder, vision_padding_block};
use super::{
    RESIDENT_IDLE_SLEEP, RESIDENT_UDP_RESPONSE_TIMEOUT, RESIDENT_UDP_SESSION_IDLE_TIMEOUT,
    ResidentDataplaneMetrics, VISION_COMMAND_CONTINUE, VLESS_RESPONSE_VERSION, XTLS_RPRX_VISION,
    XUDP_COMMAND_NEW, XUDP_MUX_TARGET, XUDP_NETWORK_UDP, XUDP_OPTION_DATA,
};

mod worker;
pub(super) use self::worker::*;
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
