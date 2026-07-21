use super::*;

pub(crate) async fn relay_tcp_over_vmess_aead_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    proxy: &mut (impl AsyncRead + AsyncWrite + Unpin),
    stop: SharedResidentStopSignal,
    session: VMessAeadTcpClientSessionStart,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    relay_tcp_over_vmess_transport_async(
        inbound,
        VmessRawTransport::new(proxy, "VMess"),
        stop,
        session,
        stats,
        metrics,
    )
    .await
}

pub(crate) async fn relay_tcp_over_vmess_websocket_aead_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    proxy: &mut (impl AsyncRead + AsyncWrite + Unpin),
    stop: SharedResidentStopSignal,
    session: VMessAeadTcpClientSessionStart,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    relay_tcp_over_vmess_transport_async(
        inbound,
        VmessWebSocketTransport::new(proxy, "VMess WebSocket"),
        stop,
        session,
        stats,
        metrics,
    )
    .await
}
