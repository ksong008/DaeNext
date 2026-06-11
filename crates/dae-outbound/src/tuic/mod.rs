pub mod contract;
pub mod dataplane;
pub mod link;
pub mod quic_loopback;
pub mod runtime;
mod tls;
pub mod underlay;
mod wire;

pub use dataplane::{
    DEFAULT_DISABLE_SNI_PROBE_LINK, DEFAULT_TRUE_QUIC_LINK, DEFAULT_TRUE_QUIC_SUBSCRIPTION_TAG,
    DEFAULT_TRUE_QUIC_UNDERLAY_MARK, TuicTrueQuicDataplaneOptions, TuicTrueQuicDataplaneReport,
    default_true_quic_options_with_timeout_ms, run_true_quic_dataplane_smoke,
};
pub use link::{TuicLink, TuicUnderlayContract};
pub use quic_loopback::{
    DEFAULT_TUIC_ALPN, DEFAULT_TUIC_HANDSHAKE_IDLE_TIMEOUT_SECS,
    DEFAULT_TUIC_INITIAL_CONNECTION_RECEIVE_WINDOW, DEFAULT_TUIC_INITIAL_STREAM_RECEIVE_WINDOW,
    DEFAULT_TUIC_KEEPALIVE_SECS, DEFAULT_TUIC_MAX_CONNECTION_RECEIVE_WINDOW,
    DEFAULT_TUIC_MAX_STREAM_RECEIVE_WINDOW, DEFAULT_TUIC_MAX_UDP_RELAY_PACKET_SIZE,
    DEFAULT_TUIC_PASSWORD, DEFAULT_TUIC_SERVER_NAME, DEFAULT_TUIC_UUID, TUIC_AUTH_TOKEN_LEN,
    TUIC_AUTHENTICATE_FRAME_LEN, TUIC_AUTHENTICATE_TYPE, TUIC_CONNECT_TYPE, TUIC_PACKET_TYPE,
    TUIC_VERSION5, TuicQuicLoopbackOptions, TuicQuicLoopbackReport, run_tuic_quic_loopback_smoke,
};
pub use runtime::{
    TuicAuthReport, authenticate_tuic_connection, build_tuic_runtime_client_config,
    write_tuic_connect_request,
};
