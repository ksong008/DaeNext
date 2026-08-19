use super::*;

pub async fn relay_tcp_over_vmess_aead_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    proxy: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    stop: SharedResidentStopSignal,
    session: VMessAeadTcpClientSessionStart,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
    leftover: Vec<u8>,
) -> Result<DirectTcpRelayStats, String> {
    relay_tcp_over_vmess_stream_async(
        inbound,
        proxy,
        stop,
        session,
        stats,
        metrics,
        VmessTransportRelayPolicy {
            label: "VMess",
            idle_error: "resident VMess relay idle timeout",
            flush_upload: false,
        },
        leftover,
    )
    .await
}

pub async fn relay_tcp_over_vmess_websocket_aead_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    proxy: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    stop: SharedResidentStopSignal,
    session: VMessAeadTcpClientSessionStart,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
    leftover: Vec<u8>,
) -> Result<DirectTcpRelayStats, String> {
    relay_tcp_over_vmess_websocket_stream_async(
        inbound,
        proxy,
        stop,
        session,
        stats,
        metrics,
        VmessTransportRelayPolicy {
            label: "VMess WebSocket",
            idle_error: "resident VMess WebSocket relay idle timeout",
            flush_upload: false,
        },
        leftover,
    )
    .await
}
