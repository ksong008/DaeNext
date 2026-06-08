use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread;
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
    socks5::{Socks5Address, udp_associate_control_over_stream, udp_packet},
    trojan::{decode_udp_packet as decode_trojan_udp_packet, packet as trojan_packet},
    tuic::{authenticate_tuic_connection, build_tuic_runtime_client_config},
    vless::packet,
    vmess,
};
use serde_json::json;
use tokio::runtime;
use tokio::time;

use super::super::PRODUCTION_NETNS;
use super::super::udp_io::{UdpOriginalDstPacket, recv_udp_with_original_dst};
use super::client::{
    VlessTlsClient, drive_tls_io_blocking, open_vless_tls_client, tls_underlay_name,
};
use super::direct::open_direct_tcp_connection;
use super::dns::{ResidentDnsPlan, handle_resident_dns_udp};
use super::events::append_event;
use super::execution::{append_runtime_execution_descriptor, udp_execution_descriptor};
use super::plan::{ResidentProxyGroupPlan, ResidentProxyPlan, ResidentProxyProtocolPlan};
use super::tcp::{
    open_marked_quic_endpoint, resolve_hysteria2_quic_remote, resolve_proxy_udp_addr,
    set_socket_mark,
};
use super::vision::{VisionUnpadState, VisionUnpadder, vision_padding_block};
use super::{
    RESIDENT_CONNECT_TIMEOUT, RESIDENT_IDLE_SLEEP, RESIDENT_UDP_RESPONSE_TIMEOUT,
    ResidentDataplaneMetrics, VISION_COMMAND_CONTINUE, VLESS_RESPONSE_VERSION, XTLS_RPRX_VISION,
    XUDP_COMMAND_NEW, XUDP_MUX_TARGET, XUDP_NETWORK_UDP, XUDP_OPTION_DATA,
};

mod worker;
pub(super) use self::worker::*;
mod packet_handler;
use self::packet_handler::*;
mod dispatch;
use self::dispatch::*;
mod probe_dns;
pub(super) use self::probe_dns::*;
mod descriptors;
use self::descriptors::*;
mod protocol_exchanges;
use self::protocol_exchanges::*;
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
#[cfg(test)]
use self::tests::*;
