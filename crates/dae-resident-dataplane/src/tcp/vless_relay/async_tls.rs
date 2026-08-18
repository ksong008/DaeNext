use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp_over_vless_tls_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    client: &mut AsyncVlessTlsClient,
    stop: SharedResidentStopSignal,
    flow: &str,
    user_uuid: [u8; 16],
    initial_payload: Vec<u8>,
    response_prefix: Vec<u8>,
    metrics: &ResidentDataplaneMetrics,
) -> Result<RelayStats, RelayError> {
    if is_xtls_rprx_vision_flow(flow) {
        relay_tcp_over_vless_vision_duplex(
            inbound,
            client,
            stop,
            user_uuid,
            initial_payload,
            response_prefix,
            metrics,
        )
        .await
    } else {
        relay_tcp_over_vless_tls_plain_duplex(
            inbound,
            client,
            stop,
            initial_payload,
            response_prefix,
            metrics,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn vless_plain_tls_relay_reuses_coalesced_flush_policy() {
        assert!(TLS_PLAIN_RELAY_FLUSH_BYTES >= 64 * 1024);
        assert!(TLS_PLAIN_RELAY_FLUSH_DELAY <= Duration::from_millis(5));
    }
}
