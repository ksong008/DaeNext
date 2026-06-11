pub mod contract;
mod dataplane;
pub mod link;
mod session_reuse_dataplane;
mod udp_packet_dataplane;

pub use dataplane::{
    AnyTlsFrame, AnyTlsSessionFrameExchangeReport, decode_frame, read_frame_from_stream,
    tcp_session_frame_exchange_over_tls_stream, write_frame_to_stream,
};
pub use link::{AnyTLSLink, AnyTLSUnderlayContract};
pub use session_reuse_dataplane::{
    AnyTlsLogicalStreamExchangeReport, AnyTlsSessionReuseExchangeReport,
    AnyTlsStreamLifecycleFrames, stream_lifecycle_frames,
    tcp_session_reuse_exchange_over_tls_stream,
};
pub use udp_packet_dataplane::{
    AnyTlsPacketWrite, AnyTlsUdpPacketStreamExchangeReport, decode_packet_first_write,
    decode_packet_next_write, udp_packet_stream_exchange_over_tls_stream,
};
