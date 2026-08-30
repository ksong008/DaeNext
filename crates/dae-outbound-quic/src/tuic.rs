pub mod runtime;
pub mod tls;
pub mod underlay;
pub mod wire;

pub use crate::congestion::QuicCongestionController as TuicCongestionController;
pub use dae_outbound_core::tuic::contract;
pub use dae_outbound_core::tuic::link;
pub use dae_outbound_core::tuic::{TuicLink, TuicUdpRelayMode, TuicUnderlayContract};
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
    DEFAULT_TUIC_SERVER_NAME,
};
pub use underlay::{TuicUnderlayAdmissionContract, admission_contract};

pub use wire::{
    TUIC_AUTH_TOKEN_LEN, TUIC_AUTHENTICATE_FRAME_LEN, TUIC_AUTHENTICATE_TYPE, TUIC_CONNECT_TYPE,
    TUIC_DISSOCIATE_FRAME_LEN, TUIC_DISSOCIATE_TYPE, TUIC_HEARTBEAT_FRAME_LEN, TUIC_HEARTBEAT_TYPE,
    TUIC_MAX_UDP_PAYLOAD_LENGTH, TUIC_MAX_UDP_STREAM_FRAME_LEN, TUIC_PACKET_TYPE, TUIC_VERSION5,
    TuicUdpPacket, build_tuic_dissociate_frame, build_tuic_heartbeat_frame, decode_tuic_udp_packet,
    decode_tuic_udp_stream_packet, encode_tuic_udp_packet, encode_tuic_udp_payload,
    encode_tuic_udp_stream_packet, encode_tuic_udp_stream_payload, fragment_tuic_udp_packet,
};
