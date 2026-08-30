pub mod auth_stream;
pub mod certchain;
pub use crate::congestion::QuicCongestionController as JuicityCongestionController;
pub use dae_outbound_core::juicity::{
    JuicityLink, JuicityPinDecode, JuicityUnderlayContract, contract, link,
};
pub mod h3_admission;
pub mod packet;
pub mod runtime;
pub mod stream_packet;
pub mod transport_packet_conn;

pub use auth_stream::{
    JUICITY_AUTHENTICATE_HEADER_LEN, JUICITY_AUTHENTICATE_TOKEN_LEN, JUICITY_AUTHENTICATE_TYPE,
    JUICITY_AUTHENTICATE_UUID_LEN, JUICITY_AUTHENTICATE_VERSION0, JuicityAuthStreamSmokeReport,
    JuicityAuthStreamTranscript, JuicityAuthenticateHeader, auth_stream_smoke,
    build_auth_stream_transcript, build_authenticate_header,
    build_deterministic_authenticate_header,
};
pub use certchain::{
    JuicityCertChainPinCheck, check_pinned_certchain, generate_cert_chain_hash,
    verify_pinned_certchain,
};
pub use h3_admission::{JuicityH3DependencyAdmission, dependency_admission};
pub use packet::{
    JUICITY_STREAM_PACKET_MAX_FRAME_LEN, JUICITY_STREAM_PACKET_MAX_METADATA_LEN,
    JUICITY_TRANSPORT_PACKET_CONN_CIPHER, JUICITY_TRANSPORT_PACKET_CONN_REUSED_INFO,
    JUICITY_UNDERLAY_AUTH_IV_LEN, JUICITY_UNDERLAY_AUTH_PSK_LEN, JuicityDialAuthRecord,
    JuicityPacketStateSmokeReport, JuicityStreamPacketFrame, JuicityStreamPacketPayload,
    JuicityUdpPacketConnDecision, JuicityUdpPacketConnKind, build_dialauth_record_for_port_zero,
    decode_stream_packet_frame, decode_stream_packet_frame_prefix,
    decode_stream_packet_payload_prefix, encode_stream_packet_frame, packet_state_smoke,
    seal_stream_packet_frame, select_udp_packet_conn, stream_packet_frame_len,
};
pub use runtime::{
    JuicityAuthReport, JuicityAuthStream, authenticate_juicity_connection,
    build_juicity_runtime_client_config, build_juicity_runtime_client_config_with_congestion,
    build_juicity_runtime_client_config_with_congestion_and_session_cache,
    build_juicity_runtime_client_config_with_session_cache, build_juicity_tcp_request,
    write_juicity_tcp_request,
};
pub use transport_packet_conn::{
    DEFAULT_TRANSPORT_PACKET_CONN_PAYLOAD, DEFAULT_TRANSPORT_PACKET_CONN_RESPONSE,
    DEFAULT_TRANSPORT_PACKET_CONN_TARGET, JUICITY_TRANSPORT_PACKET_CONN_NONCE_LEN,
    JUICITY_TRANSPORT_PACKET_CONN_REUSED_INFO_RAW, JUICITY_TRANSPORT_PACKET_CONN_TAG_LEN,
    JuicityTransportPacketConnOptions, JuicityTransportPacketConnReport, open_transport_packet,
    run_transport_packet_conn_smoke, seal_transport_packet,
};
