pub use dae_outbound_core::anytls::link::AnyTLSUnderlayContract;
pub use dae_outbound_core::anytls::{contract, link};
pub use dae_outbound_stream::anytls::{AnyTLSLink, AnyTlsFrame, AnyTlsPaddingScheme};

#[cfg(any(test, feature = "test-support"))]
mod dataplane;
#[cfg(any(test, feature = "test-support"))]
mod session_reuse_dataplane;
#[cfg(any(test, feature = "test-support"))]
mod udp_packet_dataplane;

#[cfg(any(test, feature = "test-support"))]
pub use dataplane::{AnyTlsSessionFrameExchangeReport, tcp_session_frame_exchange_over_tls_stream};
#[cfg(any(test, feature = "test-support"))]
pub use dataplane::{decode_frame, read_frame_from_stream, write_frame_to_stream};
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
