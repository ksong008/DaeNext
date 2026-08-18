use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dae_ebpf_support::open_transparent_udp_socket_bound_in_netns;
#[cfg(test)]
use dae_outbound::hysteria2::{HYSTERIA2_MAX_UDP_MESSAGE_LENGTH, decode_hysteria2_udp_message};
#[cfg(test)]
use dae_outbound::juicity::{decode_stream_packet_frame, seal_stream_packet_frame};
#[cfg(test)]
use dae_outbound::tuic::{decode_tuic_udp_packet, encode_tuic_udp_stream_packet};
use dae_outbound::{
    anytls::link as anytls_link,
    hysteria2::{
        HYSTERIA2_MAX_UDP_PAYLOAD_LENGTH, Hysteria2UdpMessage, encode_hysteria2_udp_message,
        encode_hysteria2_udp_payload, fragment_hysteria2_udp_message,
        hysteria2_udp_payload_capacity,
    },
    juicity::{
        JUICITY_STREAM_PACKET_MAX_FRAME_LEN, JuicityStreamPacketPayload,
        decode_stream_packet_payload_prefix, encode_stream_packet_frame,
    },
    shadowsocks::{
        Ss2022UdpCodec, Ss2022UdpReplayMetricsSnapshot,
        decode_udp_packet as decode_shadowsocks_udp_packet, encode_udp_packet,
        ss2022_udp_unix_timestamp_now,
    },
    shared_transport::{
        GrpcMode, HttpUpgradeOptions, http_upgrade_request, validate_http_status,
        validate_websocket_handshake_response, websocket_client_binary_frame_with_random_mask,
        websocket_client_handshake,
    },
    socks5::{Socks5Address, udp_packet},
    trojan::packet as trojan_packet,
    tuic::{
        TuicUdpPacket, TuicUdpRelayMode, encode_tuic_udp_packet, encode_tuic_udp_payload,
        encode_tuic_udp_stream_payload, fragment_tuic_udp_packet,
    },
    vless::packet,
    vmess,
};
use dae_resident_core::*;
use dae_resident_plan::*;
use dae_resident_transport::*;
use serde_json::json;
use tokio::time;

use dae_datapath::udp_io::{UdpOriginalDstPacket, UdpSendMessage, try_sendmmsg};
use dae_resident_core::events::{
    ResidentEventKind, ResidentEventMetadata, append_event, append_event_with_metadata,
};
use dae_resident_core::{append_runtime_execution_descriptor, udp_execution_descriptor};
use dae_resident_dns::ResidentDnsDispatcher;
mod task_shutdown;
pub use self::task_shutdown::*;
mod availability;
pub use self::availability::ResidentDataUdpAvailabilityHandle;
mod session_key;
pub use self::session_key::*;
mod session_actor;
pub use self::session_actor::*;
mod session_cleanup;
pub use self::session_cleanup::*;
mod direct_session;
pub use self::direct_session::*;
mod session_executor;
pub use self::session_executor::clear_connect_udp_h2_pools;
pub use self::session_executor::clear_connect_udp_h3_pools;
pub use self::session_executor::connect_udp_pool_metrics_snapshot;
#[cfg(any(test, feature = "test-support"))]
pub use self::session_executor::exercise_anytls_udp_stream_session;
#[cfg(any(test, feature = "test-support"))]
pub use self::session_executor::exercise_juicity_udp_stream_session;
#[cfg(any(test, feature = "test-support"))]
pub use self::session_executor::vless_udp_length_frame;
pub use self::session_executor::*;
#[cfg(any(test, feature = "test-support"))]
pub use self::session_executor::{ProxyUdpSessionCheckpoint, exercise_proxy_udp_packet_session};
mod vmess_session;
use self::vmess_session::*;
mod response;
pub use self::response::*;
mod packet_handler;
pub use self::packet_handler::resident_dns_udp_exchange_result;
use self::packet_handler::*;
mod descriptors;
use self::descriptors::*;
pub use self::descriptors::{
    resident_udp_proxy_handler_name, udp_packet_semantics_for_destination,
    udp_probe_packet_session_value,
};
mod stream_helpers;
use self::stream_helpers::*;
mod stream_read;
use self::stream_read::*;
mod quic_helpers;
#[cfg(any(test, feature = "test-support"))]
pub use self::quic_helpers::build_juicity_stream_packet_request;
use self::quic_helpers::*;
mod vless_xudp;
pub use self::vless_xudp::*;
mod reply;
pub use self::reply::*;
pub use self::reply::{UdpReplyDispatcher, UdpReplyHandle};

#[cfg(test)]
#[path = "tests/chain_execution.rs"]
mod chain_execution_tests;
#[cfg(test)]
mod tests;

const PRODUCTION_NETNS: &str = "daens";

fn resident_udp_socket_buffer_bytes() -> usize {
    std::env::var(RESIDENT_UDP_SOCKET_BUFFER_BYTES_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(RESIDENT_UDP_SOCKET_BUFFER_BYTES_DEFAULT)
        .clamp(
            RESIDENT_UDP_SOCKET_BUFFER_BYTES_MIN,
            RESIDENT_UDP_SOCKET_BUFFER_BYTES_MAX,
        )
}

fn apply_resident_udp_socket_buffer_tuning(socket: &std::net::UdpSocket) {
    apply_udp_socket_buffer_tuning(socket.as_raw_fd(), resident_udp_socket_buffer_bytes());
}

fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}
