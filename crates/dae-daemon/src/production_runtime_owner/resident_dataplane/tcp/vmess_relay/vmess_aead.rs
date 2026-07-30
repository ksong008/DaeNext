use super::*;

pub(crate) async fn relay_tcp_over_vmess_aead_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    proxy: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    stop: SharedResidentStopSignal,
    session: VMessAeadTcpClientSessionStart,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    relay_tcp_over_vmess_stream_async(
        inbound,
        proxy,
        stop,
        session,
        stats,
        metrics,
        "VMess",
        "resident VMess relay idle timeout",
    )
    .await
}

pub(crate) async fn relay_tcp_over_vmess_websocket_aead_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    proxy: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    stop: SharedResidentStopSignal,
    session: VMessAeadTcpClientSessionStart,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    relay_tcp_over_vmess_websocket_stream_async(
        inbound,
        proxy,
        stop,
        session,
        stats,
        metrics,
        "VMess WebSocket",
        "resident VMess WebSocket relay idle timeout",
    )
    .await
}
