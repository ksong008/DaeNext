pub mod contract;
#[cfg(any(test, feature = "test-support"))]
mod dataplane;
pub mod link;
#[cfg(any(test, feature = "test-support"))]
mod quic_loopback;
mod runtime;
mod tls;
mod underlay;
mod wire;

#[cfg(any(test, feature = "test-support"))]
pub use dataplane::{
    DEFAULT_DISABLE_SNI_PROBE_LINK, DEFAULT_TRUE_QUIC_LINK, DEFAULT_TRUE_QUIC_SUBSCRIPTION_TAG,
    DEFAULT_TRUE_QUIC_UNDERLAY_MARK, TuicTrueQuicDataplaneOptions, TuicTrueQuicDataplaneReport,
    default_true_quic_options_with_timeout_ms, run_true_quic_dataplane_smoke,
};
pub use link::{TuicLink, TuicUdpRelayMode, TuicUnderlayContract};
#[cfg(any(test, feature = "test-support"))]
pub use quic_loopback::{
    DEFAULT_TUIC_PASSWORD, DEFAULT_TUIC_UUID, TuicQuicLoopbackOptions, TuicQuicLoopbackReport,
    run_tuic_quic_loopback_smoke,
};
pub use runtime::{
    TuicAuthReport, authenticate_tuic_connection, build_tuic_runtime_client_config,
    build_tuic_runtime_client_config_with_congestion,
    build_tuic_runtime_client_config_with_session_cache, write_tuic_connect_request,
};
pub use tls::{
    DEFAULT_TUIC_ALPN, DEFAULT_TUIC_HANDSHAKE_IDLE_TIMEOUT_SECS,
    DEFAULT_TUIC_INITIAL_CONNECTION_RECEIVE_WINDOW, DEFAULT_TUIC_INITIAL_STREAM_RECEIVE_WINDOW,
    DEFAULT_TUIC_KEEPALIVE_SECS, DEFAULT_TUIC_MAX_CONNECTION_RECEIVE_WINDOW,
    DEFAULT_TUIC_MAX_STREAM_RECEIVE_WINDOW, DEFAULT_TUIC_MAX_UDP_RELAY_PACKET_SIZE,
    DEFAULT_TUIC_SERVER_NAME, TuicCongestionController,
};
pub use underlay::{TuicUnderlayAdmissionContract, admission_contract};
pub use wire::{
    TUIC_AUTH_TOKEN_LEN, TUIC_AUTHENTICATE_FRAME_LEN, TUIC_AUTHENTICATE_TYPE, TUIC_CONNECT_TYPE,
    TUIC_DISSOCIATE_FRAME_LEN, TUIC_DISSOCIATE_TYPE, TUIC_HEARTBEAT_FRAME_LEN, TUIC_HEARTBEAT_TYPE,
    TUIC_MAX_UDP_PAYLOAD_LENGTH, TUIC_PACKET_TYPE, TUIC_VERSION5, TuicUdpPacket,
    build_tuic_dissociate_frame, build_tuic_heartbeat_frame, decode_tuic_udp_packet,
    encode_tuic_udp_packet, fragment_tuic_udp_packet,
};
