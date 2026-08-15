use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use super::{
    AnyTlsLogicalStreamLease, AnyTlsOwnerRegistryHandle, H2CarrierLease,
    Hysteria2OwnerRegistryHandle, Hysteria2UdpSessionLease, JuicityOwnerRegistryHandle,
    JuicityTransportLease, ResidentTransportOwnerRegistries, SharedResidentStopSignal,
    TuicOwnerRegistryHandle, TuicUdpAssociationLease,
};
#[cfg(not(test))]
use super::{ResidentAllocatorReclaimReason, resident_allocator_request_reclaim};

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
use serde_json::json;
use tokio::time;

#[cfg(test)]
use super::RESIDENT_UDP_SESSION_IDLE_TIMEOUT_MAX;
use super::client::{
    AsyncResidentTlsClient, async_resident_tls_underlay_name,
    open_async_resident_tls_client_with_binding, open_proxy_tcp_stream_with_binding,
};
use super::dns::{
    ResidentDnsPlan, build_dns_server_failure_response, handle_resident_dns_udp_async,
};
use super::events::{
    ResidentEventKind, ResidentEventMetadata, admit_event, append_admitted_event, append_event,
    append_event_with_metadata,
};
use super::execution::{append_runtime_execution_descriptor, udp_execution_descriptor};
#[cfg(test)]
use super::plan::ResidentHysteria2ObfsPlan;
#[cfg(test)]
use super::plan::share_resident_proxy_groups;
use super::plan::{
    ResidentDataUdpAvailabilityHandle, ResidentProtocolShape, ResidentProxyBinding,
    ResidentProxyGroupPlan, ResidentProxyPlan, ResidentProxyProtocolPlan,
    ResidentStreamPacketTransport, ResidentUdpExecutionAgreement, ResidentUdpExecutionDisposition,
    ResidentUdpExecutorFactory, ResidentUdpSourceContract, ResidentUdpWireIdentityContract,
    ResidentXhttpHttpVersion, ResidentXhttpMode, SharedResidentProxyGroupMap, UdpPacketSemantics,
    resident_udp_chain_admission,
};
use super::tcp::{
    AsyncWebSocketPayloadReader, AsyncWebSocketPayloadState, GrpcH2Response, GrpcHunkReadBuffer,
    QuicEndpointCallerClass, SpawnedLogicalStream, VmessHttpHeaderStream, XhttpDownloadClient,
    XhttpPacketUpParts, XhttpPacketUpPipeline, XhttpStreamParts, XhttpStreamUploadClient,
    XhttpUploadClient, close_xhttp_download_client, close_xhttp_stream_upload_client,
    close_xhttp_upload_client, httpupgrade_handshake_over_resident_tls_async,
    inherit_quic_endpoint_observation, open_grpc_h2_stream, open_h2_body_stream,
    open_vmess_http_header_stream, open_xhttp_packet_up_parts, open_xhttp_stream_parts,
    poll_xhttp_download_data, read_xhttp_download_data, send_grpc_data, send_grpc_hunk,
    send_h2_data_with_context, send_xhttp_stream_data, set_socket_mark,
    spawn_grpc_h2_payload_stream, spawn_websocket_payload_stream,
    spawn_xhttp_packet_up_payload_stream, spawn_xhttp_stream_payload_stream,
    websocket_handshake_over_resident_tls_async,
    write_websocket_binary_frame_over_resident_tls_async,
};
use super::vision::{VisionUnpadder, vision_padding_block};
use super::{
    RESIDENT_IDLE_SLEEP, RESIDENT_RUNTIME_FORCED_TASK_JOIN_GRACE,
    RESIDENT_UDP_DNS_SESSION_IDLE_TIMEOUT, RESIDENT_UDP_RESPONSE_TIMEOUT, ResidentDataplaneMetrics,
    ResidentHealthResuscitationHandle, ResidentUdpRuntimeConfig, VISION_COMMAND_CONTINUE,
    VLESS_RESPONSE_VERSION, XUDP_COMMAND_KEEP, XUDP_COMMAND_NEW, XUDP_MUX_TARGET, XUDP_NETWORK_UDP,
    XUDP_OPTION_DATA, apply_resident_udp_socket_buffer_tuning, resident_socket_addr_display,
    resident_udp_network_name,
};
use crate::PRODUCTION_NETNS;
#[cfg(test)]
use dae_datapath::udp_io::UdpOriginalDstRecvError;
use dae_datapath::udp_io::{
    UdpBatchReceiver, UdpOriginalDstPacket, UdpPayloadPool, UdpSendMessage, try_sendmmsg,
};

mod admission;
mod worker;
pub(super) use self::worker::*;
pub(crate) use admission::{
    ResidentUdpPayloadAdmission, ResidentUdpPayloadAdmissionError, ResidentUdpPayloadPermit,
    admit_udp_payload,
};
mod task_shutdown;
use self::task_shutdown::*;
mod session_key;
use self::session_key::*;
mod manager;
pub(crate) use self::manager::ResidentUdpGenerationPlan;
use self::manager::*;
mod session_actor;
use self::session_actor::*;
mod session_cleanup;
use self::session_cleanup::*;
mod direct_session;
use self::direct_session::*;
mod session_executor;
pub(crate) use self::session_executor::clear_connect_udp_h2_pools;
pub(crate) use self::session_executor::clear_connect_udp_h3_pools;
pub(crate) use self::session_executor::connect_udp_pool_metrics_snapshot;
#[cfg(test)]
pub(crate) use self::session_executor::exercise_anytls_udp_stream_session;
#[cfg(test)]
pub(crate) use self::session_executor::exercise_juicity_udp_stream_session;
use self::session_executor::*;
#[cfg(test)]
pub(crate) use self::session_executor::{
    ProxyUdpSessionCheckpoint, exercise_proxy_udp_packet_session,
};
mod vmess_session;
use self::vmess_session::*;
mod response;
use self::response::*;
mod packet_handler;
use self::packet_handler::*;
mod proxy_dns_forwarder;
pub(super) use self::proxy_dns_forwarder::*;
mod probe_dns;
pub(super) use self::probe_dns::*;
mod descriptors;
pub(crate) use self::descriptors::resident_udp_proxy_handler_name;
use self::descriptors::*;
mod stream_helpers;
use self::stream_helpers::*;
mod stream_read;
use self::stream_read::*;
mod quic_helpers;
#[cfg(test)]
pub(crate) use self::quic_helpers::build_juicity_stream_packet_request;
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
