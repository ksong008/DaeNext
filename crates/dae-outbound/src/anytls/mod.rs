pub mod contract;
mod dataplane;
pub mod link;
mod padding;
#[cfg(any(test, feature = "test-support"))]
mod session_reuse_dataplane;
#[cfg(any(test, feature = "test-support"))]
mod udp_packet_dataplane;

pub use dataplane::AnyTlsFrame;
#[cfg(any(test, feature = "test-support"))]
pub use dataplane::{AnyTlsSessionFrameExchangeReport, tcp_session_frame_exchange_over_tls_stream};
#[cfg(any(test, feature = "test-support"))]
pub use dataplane::{decode_frame, read_frame_from_stream, write_frame_to_stream};
pub use link::{AnyTLSLink, AnyTLSUnderlayContract};
pub use padding::AnyTlsPaddingScheme;
#[cfg(any(test, feature = "test-support"))]
pub use session_reuse_dataplane::{
    AnyTlsLogicalStreamExchangeReport, AnyTlsSessionReuseExchangeReport,
    AnyTlsStreamLifecycleFrames, stream_lifecycle_frames,
    tcp_session_reuse_exchange_over_tls_stream,
};
#[cfg(any(test, feature = "test-support"))]
pub use udp_packet_dataplane::{
    AnyTlsPacketWrite, AnyTlsUdpPacketStreamExchangeReport, decode_packet_first_write,
    decode_packet_next_write, udp_packet_stream_exchange_over_tls_stream,
};
