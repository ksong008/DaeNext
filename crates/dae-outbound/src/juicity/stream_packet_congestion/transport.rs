use super::*;
pub(super) fn bbr_transport_config() -> Result<quinn::TransportConfig, OutboundError> {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(DEFAULT_H3_KEEPALIVE_SECS)));
    transport.max_idle_timeout(Some(
        Duration::from_secs(DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS)
            .try_into()
            .map_err(|err| {
                bad_stream_packet_congestion(format!("h3 idle timeout config: {err}"))
            })?,
    ));
    transport.datagram_receive_buffer_size(None);
    transport.datagram_send_buffer_size(0);
    let mut bbr = quinn::congestion::BbrConfig::default();
    bbr.initial_window(RUST_BBR_INITIAL_WINDOW_BYTES);
    transport.congestion_controller_factory(Arc::new(bbr));
    Ok(transport)
}

pub(super) fn bad_stream_packet_congestion(message: impl Into<String>) -> OutboundError {
    OutboundError::BadJuicity(message.into())
}
