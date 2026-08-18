use super::*;

pub async fn relay_tcp_over_vmess_tls_aead_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    client: &mut AsyncResidentTlsClient,
    stop: SharedResidentStopSignal,
    session: VMessAeadTcpClientSessionStart,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
    leftover: Vec<u8>,
) -> Result<DirectTcpRelayStats, String> {
    relay_tcp_over_vmess_stream_async(
        inbound,
        client,
        stop,
        session,
        stats,
        metrics,
        VmessTransportRelayPolicy {
            label: "VMess TLS",
            idle_error: "resident VMess TLS relay idle timeout",
            flush_upload: true,
        },
        leftover,
    )
    .await
}

pub async fn relay_tcp_over_vmess_websocket_tls_aead_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    client: &mut AsyncResidentTlsClient,
    stop: SharedResidentStopSignal,
    session: VMessAeadTcpClientSessionStart,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
    leftover: Vec<u8>,
) -> Result<DirectTcpRelayStats, String> {
    relay_tcp_over_vmess_websocket_stream_async(
        inbound,
        client,
        stop,
        session,
        stats,
        metrics,
        VmessTransportRelayPolicy {
            label: "VMess TLS WebSocket",
            idle_error: "resident VMess TLS WebSocket relay idle timeout",
            flush_upload: false,
        },
        leftover,
    )
    .await
}
