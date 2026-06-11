pub mod contract;
pub mod dataplane;
pub mod link;
pub mod port_hopping;
pub mod quic_loopback;
pub mod runtime;
mod tls;
pub mod underlay;
mod wire;

pub use dataplane::{
    DEFAULT_TRUE_QUIC_LINK, DEFAULT_TRUE_QUIC_PORT_HOP_ITERATIONS,
    DEFAULT_TRUE_QUIC_SUBSCRIPTION_TAG, DEFAULT_TRUE_QUIC_UDP_HOP_INTERVAL_MS,
    DEFAULT_TRUE_QUIC_UNDERLAY_MARK, Hysteria2TrueQuicDataplaneOptions,
    Hysteria2TrueQuicDataplaneReport, default_true_quic_options_with_timeout_ms,
    run_true_quic_dataplane_smoke,
};
pub use link::{Hysteria2Link, Hysteria2ServerContract, server_contract};
pub use port_hopping::{Hysteria2PortHopSchedule, build_port_hop_schedule, parse_port_union};
pub use quic_loopback::{
    DEFAULT_HYSTERIA2_ALPN, DEFAULT_HYSTERIA2_KEEPALIVE_SECS,
    DEFAULT_HYSTERIA2_MAX_IDLE_TIMEOUT_SECS, DEFAULT_HYSTERIA2_SERVER_NAME,
    HYSTERIA2_FRAME_TYPE_TCP_REQUEST, Hysteria2QuicLoopbackOptions, Hysteria2QuicLoopbackReport,
    run_hysteria2_quic_loopback_smoke,
};
pub use runtime::{
    Hysteria2AuthReport, Hysteria2TcpResponseHead, authenticate_hysteria2_connection,
    read_hysteria2_tcp_response, write_hysteria2_tcp_request,
};
pub use tls::build_hysteria2_pinned_client_config;
pub use underlay::{
    Hysteria2PinSha256Check, Hysteria2UnderlayContract, pin_sha256_matches_raw_cert,
    raw_cert_sha256_hex, underlay_contract,
};
