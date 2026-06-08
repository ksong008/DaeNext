use std::collections::{BTreeMap, VecDeque};
use std::future::poll_fn;
use std::io::{ErrorKind, Read, Write};
use std::mem::size_of;
use std::net::{
    IpAddr, Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, ToSocketAddrs,
    UdpSocket,
};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::slice;
use std::sync::{
    Arc, Condvar, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dae_core_types::OutboundIndex;
use dae_datapath::{
    OUTBOUND_BLOCK, OUTBOUND_CONTROL_PLANE_ROUTING, OUTBOUND_DIRECT, TcpDialMode,
    TcpDirectDialReport, choose_dial_target,
};
use dae_ebpf_support::{
    BpfIpBytes, BpfRoutingResult, BpfTuplesKey, lookup_map_elem_bytes, open_map_fd,
};
use dae_outbound::{
    anytls::{AnyTlsFrame, contract as anytls_contract, link as anytls_link},
    http_proxy::{HttpConnectOptions, request as http_request},
    hysteria2::{
        authenticate_hysteria2_connection, build_hysteria2_pinned_client_config,
        read_hysteria2_tcp_response, write_hysteria2_tcp_request,
    },
    juicity::{
        authenticate_juicity_connection, build_juicity_runtime_client_config,
        write_juicity_tcp_request,
    },
    shadowsocks::{
        AeadStreamCodec, ShadowsocksMetadata, Sip003SimpleObfsHttpOptions,
        Sip003SimpleObfsTlsOptions, cipher_spec, read_encrypted_chunk_from_stream,
        simple_obfs_http_request_with_body, simple_obfs_tls_client_hello_with_body,
        ss2022_tcp_client_stream_encoder, ss2022_tcp_server_stream_decoder,
        ss2022_tcp_unix_timestamp_now,
    },
    shared_transport::mux::MuxFrameOptions,
    shared_transport::{
        HttpUpgradeOptions, MeekRoundTripOptions, grpc_hunk_frame, grpc_hunk_payload, ir,
        meek_http_request, mux_data_frame, mux_end_frame, mux_new_frame, validate_http_status,
    },
    socks5::{Socks5Address, handshake},
    trojan::packet as trojan_packet,
    tuic::{
        authenticate_tuic_connection, build_tuic_runtime_client_config, write_tuic_connect_request,
    },
    vless::packet,
    vmess::{
        VMessAeadTcpClientSessionStart, aead_tcp_client_session_start,
        aead_tcp_response_reader_from_async_stream, aead_tcp_response_reader_from_stream,
    },
};
use dae_routing::{Query, RoutingMatcher};
use dae_sniffing::{SniffingError, sniff_tcp};
use rustls::{ClientConfig, ClientConnection, RootCertStore, pki_types::ServerName};
use serde_json::{Value, json};

use super::ResidentDataplaneMetrics;
use super::client::{
    AsyncResidentTlsClient, AsyncVlessTlsClient, TlsDriveOutcome, VlessTlsClient,
    async_resident_tls_underlay_name, async_tls_underlay_name, drive_tls_io_record_aware,
    open_async_resident_tls_client, open_async_vless_tls_client, open_vless_tls_client,
    tls_underlay_name,
};
use super::direct::{
    DirectTcpConnection, DirectTcpRelayStats, open_direct_tcp_connection,
    open_direct_tcp_connection_async, relay_tcp_direct, relay_tcp_direct_async,
};
use super::events::append_event;
use super::execution::{append_runtime_execution_descriptor, tcp_execution_descriptor};
use super::io::write_all_nonblocking;
use super::plan::{ResidentProxyGroupPlan, ResidentProxyPlan, ResidentProxyProtocolPlan};
use super::vision::{
    VisionInnerTlsState, VisionUnpadder, VisionUplinkMode, drain_vision_uplink,
    drain_vision_uplink_async,
};
use super::{
    RESIDENT_CONNECT_TIMEOUT, RESIDENT_IDLE_SLEEP, RESIDENT_TCP_ACCEPT_SLEEP,
    RESIDENT_TCP_IDLE_TIMEOUT, TLS_RECORD_MAX_PAYLOAD_LEN, VLESS_RESPONSE_VERSION,
    XTLS_RPRX_VISION,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};
use tokio::runtime;
use tokio::time;

mod shadowsocks_stream;
mod websocket;

use shadowsocks_stream::{
    AsyncV2rayPluginMuxPayloadState, AsyncWebSocketPayloadReader, AsyncWebSocketPayloadState,
    read_shadowsocks_aead_chunk_from_v2ray_plugin_mux,
    read_shadowsocks_aead_chunk_from_websocket_tls,
};
use websocket::{
    WebSocketBinaryFrameDecoder, WebSocketPayloadReader, httpupgrade_handshake_over_plain_stream,
    httpupgrade_handshake_over_resident_tls_async, websocket_handshake_over_plain_stream,
    websocket_handshake_over_resident_tls_async,
    write_websocket_binary_frame_over_resident_tls_async, write_websocket_binary_frame_to_stream,
};

include!("tcp/router.rs");
include!("tcp/probe.rs");
include!("tcp/accept_loop.rs");
include!("tcp/vless_handlers.rs");
include!("tcp/proxy_dispatch.rs");
include!("tcp/plain_handlers.rs");
include!("tcp/vmess_handlers.rs");
include!("tcp/transport_helpers.rs");
include!("tcp/stream_helpers.rs");
include!("tcp/shadowsocks_relay.rs");
include!("tcp/vmess_relay.rs");
include!("tcp/event_builders.rs");
include!("tcp/direct_sniffing.rs");
include!("tcp/vless_relay.rs");
include!("tcp/tests.rs");
