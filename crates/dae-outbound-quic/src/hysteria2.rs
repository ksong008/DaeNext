pub mod auth;
pub mod capability;
pub mod congestion;
pub mod padding;
pub mod runtime;
pub mod tls;
pub mod underlay;
pub mod wire;

pub use dae_outbound_core::hysteria2::contract;
pub use dae_outbound_core::hysteria2::port_hopping::{
    HYSTERIA2_MIN_PORT_HOP_INTERVAL, Hysteria2PortHopSchedule, build_port_hop_schedule,
    parse_port_union,
};
pub use dae_outbound_core::hysteria2::{
    Hysteria2ApplicationProtocol, Hysteria2BbrProfile, Hysteria2CertificateVerification,
    Hysteria2ClientCertificateIdentity, Hysteria2CongestionConfig, Hysteria2CongestionController,
    Hysteria2CongestionNegotiation, Hysteria2EffectiveCongestionController,
    Hysteria2EncryptedClientHelloIdentity, Hysteria2Link, Hysteria2ServerContract,
    Hysteria2TlsIdentity, Hysteria2TlsPolicy, Hysteria2TrustAnchorIdentity, server_contract,
};
pub use dae_outbound_core::hysteria2::{link, tls_policy};

pub use auth::{
    Hysteria2AuthReport, Hysteria2AuthenticatedSession, authenticate_hysteria2_connection,
};
pub use capability::{
    Hysteria2CapabilityDisposition, Hysteria2CapabilityLedgerEntry, hysteria2_capability_ledger,
};
pub use congestion::{
    Hysteria2CongestionRuntime, Hysteria2ServerBandwidthResponse, parse_hysteria2_bandwidth,
};
pub use padding::{
    HYSTERIA2_AUTH_PADDING_MAX_EXCLUSIVE, HYSTERIA2_AUTH_PADDING_MIN,
    HYSTERIA2_TCP_REQUEST_PADDING_MAX_EXCLUSIVE, HYSTERIA2_TCP_REQUEST_PADDING_MIN,
    Hysteria2PaddingMetricsSnapshot, hysteria2_padding_metrics_snapshot,
};
pub use runtime::{
    Hysteria2TcpResponseHead, read_hysteria2_tcp_response, write_hysteria2_tcp_request,
};
pub use tls::{
    DEFAULT_HYSTERIA2_ALPN, DEFAULT_HYSTERIA2_KEEPALIVE_SECS,
    DEFAULT_HYSTERIA2_MAX_IDLE_TIMEOUT_SECS, DEFAULT_HYSTERIA2_MTU_DISCOVERY_UPPER_BOUND,
    DEFAULT_HYSTERIA2_SERVER_NAME, build_hysteria2_runtime_client_config,
    build_hysteria2_runtime_client_config_with_congestion,
    build_hysteria2_runtime_client_config_with_session_cache,
    build_hysteria2_runtime_client_config_with_udp_overhead,
};
pub use underlay::{
    Hysteria2PinSha256Check, Hysteria2UnderlayContract, pin_sha256_matches_raw_cert,
    raw_cert_sha256_hex, underlay_contract,
};

pub const HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD: usize = 8;

pub use wire::{
    HYSTERIA2_FRAME_TYPE_TCP_REQUEST, HYSTERIA2_MAX_UDP_ADDRESS_LENGTH,
    HYSTERIA2_MAX_UDP_MESSAGE_LENGTH, HYSTERIA2_MAX_UDP_PAYLOAD_LENGTH, Hysteria2UdpMessage,
    decode_hysteria2_udp_message, encode_hysteria2_udp_message, encode_hysteria2_udp_payload,
    fragment_hysteria2_udp_message, hysteria2_udp_payload_capacity,
};
