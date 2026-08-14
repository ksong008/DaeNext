#[cfg(any(test, feature = "test-support"))]
pub mod auth_lifecycle;
pub mod auth_stream;
#[cfg(any(test, feature = "test-support"))]
pub mod auth_stream_ekm;
#[cfg(any(test, feature = "test-support"))]
pub mod auth_stream_live;
pub mod certchain;
#[cfg(any(test, feature = "test-support"))]
pub mod client_integration;
pub mod contract;
pub mod h3_admission;
#[cfg(any(test, feature = "test-support"))]
pub mod h3_loopback;
pub mod link;
#[cfg(any(test, feature = "test-support"))]
pub mod outbound_dataplane;
pub mod packet;
pub mod runtime;
#[cfg(any(test, feature = "test-support"))]
pub mod stream_packet_congestion;
#[cfg(any(test, feature = "test-support"))]
pub mod stream_packet_conn;
pub mod transport_packet_conn;

pub use crate::shared_transport::QuicCongestionController as JuicityCongestionController;
#[cfg(any(test, feature = "test-support"))]
pub use auth_lifecycle::{
    DEFAULT_AUTH_LIFECYCLE_RECORD_COUNT, DEFAULT_AUTH_LIFECYCLE_TARGETS,
    JuicityAuthLifecycleOptions, JuicityAuthLifecycleReport, run_auth_lifecycle_smoke,
};
pub use auth_stream::{
    JUICITY_AUTHENTICATE_HEADER_LEN, JUICITY_AUTHENTICATE_TOKEN_LEN, JUICITY_AUTHENTICATE_TYPE,
    JUICITY_AUTHENTICATE_UUID_LEN, JUICITY_AUTHENTICATE_VERSION0, JuicityAuthStreamSmokeReport,
    JuicityAuthStreamTranscript, JuicityAuthenticateHeader, auth_stream_smoke,
    build_auth_stream_transcript, build_authenticate_header,
    build_deterministic_authenticate_header,
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
pub use certchain::{
    JuicityCertChainPinCheck, check_pinned_certchain, generate_cert_chain_hash,
    verify_pinned_certchain,
};
#[cfg(any(test, feature = "test-support"))]
pub use client_integration::{
    DEFAULT_CLIENT_INTEGRATION_AUTH_ITERATIONS, DEFAULT_CLIENT_INTEGRATION_CONGESTION_ITERATIONS,
    DEFAULT_CLIENT_INTEGRATION_MAX_IN_FLIGHT, DEFAULT_CLIENT_INTEGRATION_STREAM_ITERATIONS,
    DEFAULT_CLIENT_INTEGRATION_TRANSPORT_ITERATIONS, JuicityClientIntegrationOptions,
    JuicityClientIntegrationReport, run_client_integration_smoke,
};
pub use h3_admission::{JuicityH3DependencyAdmission, dependency_admission};
#[cfg(any(test, feature = "test-support"))]
pub use h3_loopback::{
    DEFAULT_H3_ALPN, DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS, DEFAULT_H3_KEEPALIVE_SECS,
    DEFAULT_H3_LOOPBACK_PAYLOAD, DEFAULT_H3_SERVER_NAME, JuicityH3LoopbackOptions,
    JuicityH3LoopbackReport, run_h3_loopback_smoke,
};
pub use link::{JuicityLink, JuicityPinDecode, JuicityUnderlayContract};
#[cfg(any(test, feature = "test-support"))]
pub use outbound_dataplane::{
    DEFAULT_OUTBOUND_DATAPLANE_ADD_LATENCY_MS, DEFAULT_OUTBOUND_DATAPLANE_ALIVE,
    DEFAULT_OUTBOUND_DATAPLANE_GROUP_NAME, DEFAULT_OUTBOUND_DATAPLANE_HEALTH_LATENCIES_MS,
    DEFAULT_OUTBOUND_DATAPLANE_LINKS, DEFAULT_OUTBOUND_DATAPLANE_SUBSCRIPTION_TAG,
    JuicityOutboundDataplaneOptions, JuicityOutboundDataplaneReport, network_type_label,
    run_outbound_dataplane_smoke,
};
pub use packet::{
    JUICITY_STREAM_PACKET_MAX_FRAME_LEN, JUICITY_STREAM_PACKET_MAX_METADATA_LEN,
    JUICITY_UNDERLAY_AUTH_IV_LEN, JUICITY_UNDERLAY_AUTH_PSK_LEN, JuicityDialAuthRecord,
    JuicityPacketStateSmokeReport, JuicityStreamPacketFrame, JuicityUdpPacketConnDecision,
    JuicityUdpPacketConnKind, build_dialauth_record_for_port_zero, decode_stream_packet_frame,
    decode_stream_packet_frame_prefix, packet_state_smoke, seal_stream_packet_frame,
    select_udp_packet_conn, stream_packet_frame_len,
};
pub use runtime::{
    JuicityAuthReport, JuicityAuthStream, authenticate_juicity_connection,
    build_juicity_runtime_client_config, build_juicity_runtime_client_config_with_congestion,
    build_juicity_runtime_client_config_with_congestion_and_session_cache,
    build_juicity_runtime_client_config_with_session_cache, build_juicity_tcp_request,
    write_juicity_tcp_request,
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
pub use transport_packet_conn::{
    DEFAULT_TRANSPORT_PACKET_CONN_PAYLOAD, DEFAULT_TRANSPORT_PACKET_CONN_RESPONSE,
    DEFAULT_TRANSPORT_PACKET_CONN_TARGET, JUICITY_TRANSPORT_PACKET_CONN_CIPHER,
    JUICITY_TRANSPORT_PACKET_CONN_NONCE_LEN, JUICITY_TRANSPORT_PACKET_CONN_REUSED_INFO_RAW,
    JUICITY_TRANSPORT_PACKET_CONN_TAG_LEN, JuicityTransportPacketConnOptions,
    JuicityTransportPacketConnReport, open_transport_packet, run_transport_packet_conn_smoke,
    seal_transport_packet,
};
