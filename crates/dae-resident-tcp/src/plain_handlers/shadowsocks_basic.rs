use super::*;

#[allow(clippy::too_many_arguments)]
pub async fn handle_shadowsocks_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    cipher: &str,
    password: &str,
    salt_len: usize,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream_async(&selection).await?;
    let initial_payload = sniff.take_payload();
    let stats = relay_tcp_over_shadowsocks_aead_async(
        inbound,
        &mut proxy,
        stop,
        &selection.route.dial_target,
        cipher,
        password,
        salt_len,
        initial_payload,
        metrics,
    )
    .await;
    stats
        .map(|stats| {
            generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "shadowsocks",
                &stats,
                "plain-tcp-relay",
            )
        })
        .or_else(|err| {
            Ok::<Value, String>(generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "shadowsocks",
                &err,
                "plain-tcp-relay",
            ))
        })
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_shadowsocks_2022_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    cipher: &str,
    password: &str,
    salt_len: usize,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream_async(&selection).await?;
    let initial_payload = sniff.take_payload();
    let stats = relay_tcp_over_shadowsocks_2022_async(
        inbound,
        &mut proxy,
        stop,
        &selection.route.dial_target,
        cipher,
        password,
        salt_len,
        initial_payload,
        metrics,
    )
    .await;
    stats
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "shadowsocks",
                &stats,
                "shadowsocks-2022-tcp",
            );
            append_proxy_tcp_execution_fields(
                &mut event,
                "shadowsocks-2022-tcp",
                "shadowsocks",
                Some("aead-2022"),
                None,
            );
            event
        })
        .or_else(|err| {
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "shadowsocks",
                &err,
                "shadowsocks-2022-tcp",
            );
            append_proxy_tcp_execution_fields(
                &mut event,
                "shadowsocks-2022-tcp",
                "shadowsocks",
                Some("aead-2022"),
                None,
            );
            Ok::<Value, String>(event)
        })
}
