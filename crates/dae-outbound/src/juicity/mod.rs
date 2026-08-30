#[cfg(any(test, feature = "test-support"))]
pub mod auth_lifecycle;
#[cfg(any(test, feature = "test-support"))]
pub mod auth_stream_ekm;
#[cfg(any(test, feature = "test-support"))]
pub mod auth_stream_live;
#[cfg(any(test, feature = "test-support"))]
pub mod client_integration;
#[cfg(any(test, feature = "test-support"))]
pub mod h3_loopback;
#[cfg(any(test, feature = "test-support"))]
pub mod outbound_dataplane;
#[cfg(any(test, feature = "test-support"))]
pub mod stream_packet_congestion;
#[cfg(any(test, feature = "test-support"))]
pub mod stream_packet_conn;

#[cfg(any(test, feature = "test-support"))]
pub mod auth_stream {
    pub use dae_outbound_quic::juicity::auth_stream::*;
}
#[cfg(any(test, feature = "test-support"))]
pub mod certchain {
    pub use dae_outbound_quic::juicity::certchain::*;
}
#[cfg(any(test, feature = "test-support"))]
pub mod contract {
    pub use dae_outbound_core::juicity::contract::*;
}
#[cfg(any(test, feature = "test-support"))]
pub mod h3_admission {
    pub use dae_outbound_quic::juicity::h3_admission::*;
}
#[cfg(any(test, feature = "test-support"))]
pub mod link {
    pub use dae_outbound_core::juicity::link::*;
}
#[cfg(any(test, feature = "test-support"))]
pub mod packet {
    pub use dae_outbound_quic::juicity::packet::*;
}
#[cfg(any(test, feature = "test-support"))]
pub mod runtime {
    pub use dae_outbound_quic::juicity::runtime::*;
}
#[cfg(any(test, feature = "test-support"))]
pub mod transport_packet_conn {
    pub use dae_outbound_quic::juicity::transport_packet_conn::*;
}

pub use dae_outbound_quic::juicity::*;

#[cfg(any(test, feature = "test-support"))]
pub use auth_lifecycle::{
    DEFAULT_AUTH_LIFECYCLE_RECORD_COUNT, DEFAULT_AUTH_LIFECYCLE_TARGETS,
    JuicityAuthLifecycleOptions, JuicityAuthLifecycleReport, run_auth_lifecycle_smoke,
};
#[cfg(any(test, feature = "test-support"))]
pub use auth_stream_ekm::{
    DEFAULT_LIVE_EKM_AUTH_PASSWORD, DEFAULT_LIVE_EKM_AUTH_TARGET, JuicityLiveEkmAuthOptions,
    JuicityLiveEkmAuthReport, run_live_ekm_auth_smoke,
};
#[cfg(any(test, feature = "test-support"))]
pub use auth_stream_live::{
    DEFAULT_LIVE_AUTH_STREAM_TARGET, JuicityLiveAuthStreamOptions, JuicityLiveAuthStreamReport,
    run_live_auth_stream_smoke,
};
#[cfg(any(test, feature = "test-support"))]
pub use client_integration::{
    DEFAULT_CLIENT_INTEGRATION_AUTH_ITERATIONS, DEFAULT_CLIENT_INTEGRATION_CONGESTION_ITERATIONS,
    DEFAULT_CLIENT_INTEGRATION_MAX_IN_FLIGHT, DEFAULT_CLIENT_INTEGRATION_STREAM_ITERATIONS,
    DEFAULT_CLIENT_INTEGRATION_TRANSPORT_ITERATIONS, JuicityClientIntegrationOptions,
    JuicityClientIntegrationReport, run_client_integration_smoke,
};
#[cfg(any(test, feature = "test-support"))]
pub use h3_loopback::{
    DEFAULT_H3_ALPN, DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS, DEFAULT_H3_KEEPALIVE_SECS,
    DEFAULT_H3_LOOPBACK_PAYLOAD, DEFAULT_H3_SERVER_NAME, JuicityH3LoopbackOptions,
    JuicityH3LoopbackReport, run_h3_loopback_smoke,
};
#[cfg(any(test, feature = "test-support"))]
pub use outbound_dataplane::{
    DEFAULT_OUTBOUND_DATAPLANE_ADD_LATENCY_MS, DEFAULT_OUTBOUND_DATAPLANE_ALIVE,
    DEFAULT_OUTBOUND_DATAPLANE_GROUP_NAME, DEFAULT_OUTBOUND_DATAPLANE_HEALTH_LATENCIES_MS,
    DEFAULT_OUTBOUND_DATAPLANE_LINKS, DEFAULT_OUTBOUND_DATAPLANE_SUBSCRIPTION_TAG,
    JuicityOutboundDataplaneOptions, JuicityOutboundDataplaneReport, network_type_label,
    run_outbound_dataplane_smoke,
};
#[cfg(any(test, feature = "test-support"))]
pub use stream_packet_congestion::{
    BBR_INITIAL_CONGESTION_WINDOW_PACKETS, BBR_INITIAL_PACKET_SIZE_IPV4,
    DEFAULT_STREAM_PACKET_CONGESTION_CONTROL, DEFAULT_STREAM_PACKET_CONGESTION_ITERATIONS,
    DEFAULT_STREAM_PACKET_CONGESTION_MAX_IN_FLIGHT, DEFAULT_STREAM_PACKET_CONGESTION_PAYLOAD_LEN,
    DEFAULT_STREAM_PACKET_CONGESTION_RESPONSE_LEN,
    DEFAULT_STREAM_PACKET_CONGESTION_RESPONSE_TARGET, DEFAULT_STREAM_PACKET_CONGESTION_TARGET,
    JUICITY_CONGESTION_CWND_PARAM, JUICITY_CONGESTION_DEFAULT,
    JuicityStreamPacketCongestionOptions, JuicityStreamPacketCongestionReport,
    RUST_BBR_INITIAL_WINDOW_BYTES, default_congestion_payload, normalize_congestion_control,
    run_stream_packet_congestion_smoke,
};
#[cfg(any(test, feature = "test-support"))]
pub use stream_packet_conn::{
    DEFAULT_STREAM_PACKET_CONN_PAYLOAD, DEFAULT_STREAM_PACKET_CONN_RESPONSE,
    DEFAULT_STREAM_PACKET_CONN_RESPONSE_TARGET, DEFAULT_STREAM_PACKET_CONN_TARGET,
    JuicityStreamPacketConnOptions, JuicityStreamPacketConnReport, run_stream_packet_conn_smoke,
};
