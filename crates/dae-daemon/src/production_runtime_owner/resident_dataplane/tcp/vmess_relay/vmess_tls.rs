use super::*;

pub(crate) async fn relay_tcp_over_vmess_tls_aead_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    client: &mut AsyncResidentTlsClient,
    stop: SharedResidentStopSignal,
    session: VMessAeadTcpClientSessionStart,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    relay_tcp_over_vmess_transport_async(
        inbound,
        VmessRawTransport::new(client, "VMess TLS"),
        stop,
        session,
        stats,
        metrics,
    )
    .await
}

pub(crate) async fn relay_tcp_over_vmess_websocket_tls_aead_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    client: &mut AsyncResidentTlsClient,
    stop: SharedResidentStopSignal,
    session: VMessAeadTcpClientSessionStart,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    relay_tcp_over_vmess_transport_async(
        inbound,
        VmessWebSocketTransport::new(client, "VMess TLS WebSocket"),
        stop,
        session,
        stats,
        metrics,
    )
    .await
}
