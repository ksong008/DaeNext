use super::*;

pub(crate) async fn relay_tcp_over_vmess_tls_aead_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    client: &mut AsyncResidentTlsClient,
    stop: SharedResidentStopSignal,
    session: VMessAeadTcpClientSessionStart,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    relay_tcp_over_vmess_stream_async(
        inbound,
        client,
        stop,
        session,
        stats,
        metrics,
        "VMess TLS",
        "resident VMess TLS relay idle timeout",
    )
    .await
}

pub(crate) async fn relay_tcp_over_vmess_websocket_tls_aead_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    client: &mut AsyncResidentTlsClient,
    stop: SharedResidentStopSignal,
    session: VMessAeadTcpClientSessionStart,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    relay_tcp_over_vmess_websocket_stream_async(
        inbound,
        client,
        stop,
        session,
        stats,
        metrics,
        "VMess TLS WebSocket",
        "resident VMess TLS WebSocket relay idle timeout",
    )
    .await
}
