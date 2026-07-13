use super::*;

pub(super) async fn handle_basic_stream_proxy_async(
    mut inbound: TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: TcpSniffReport,
    metrics: Arc<ResidentDataplaneMetrics>,
) -> Result<Value, String> {
    let execution = selection.proxy.execution_plan();
    match &selection.proxy.handler {
        ResidentProxyProtocolPlan::Socks5Tcp { username, password } => {
            let username = username.clone();
            let password = password.clone();
            handle_socks5_proxy_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                stop,
                &sniff,
                &metrics,
                &username,
                &password,
            )
            .await
        }
        ResidentProxyProtocolPlan::HttpProxyTcp {
            username,
            password,
            transport,
            transport_host,
            transport_path,
        } => {
            let username = username.clone();
            let password = password.clone();
            let transport = *transport;
            let transport_host = transport_host.clone();
            let transport_path = transport_path.clone();
            if execution.security == ResidentSecurityUnderlayPlan::None {
                handle_http_proxy_tcp_connection_async(
                    &mut inbound,
                    peer,
                    original_dst,
                    selection,
                    stop,
                    &sniff,
                    &metrics,
                    &username,
                    &password,
                    transport,
                    &transport_host,
                    &transport_path,
                )
                .await
            } else if execution.security.is_tls_stream() {
                handle_https_proxy_tcp_connection_async(
                    &mut inbound,
                    peer,
                    original_dst,
                    selection,
                    stop,
                    &sniff,
                    &metrics,
                    &username,
                    &password,
                    transport,
                    &transport_host,
                    &transport_path,
                )
                .await
            } else {
                Err(format!(
                    "resident HTTP CONNECT dispatcher rejects security underlay {:?}",
                    execution.security
                ))
            }
        }
        handler => Err(format!(
            "resident basic TCP dispatcher received incompatible handler {handler:?}"
        )),
    }
}
