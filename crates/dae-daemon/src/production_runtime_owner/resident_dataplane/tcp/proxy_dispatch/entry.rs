use super::*;
pub(crate) async fn handle_frame_tls_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    match &selection.proxy.handler {
        ResidentProxyProtocolPlan::TrojanTcpTls { password } => {
            let password = password.clone();
            if selection.proxy.net == "websocket" {
                handle_trojan_websocket_tls_tcp_connection_async(
                    inbound,
                    peer,
                    original_dst,
                    selection,
                    stop,
                    sniff,
                    metrics,
                    &password,
                )
                .await
            } else if selection.proxy.net == "httpupgrade" {
                handle_trojan_httpupgrade_tls_tcp_connection_async(
                    inbound,
                    peer,
                    original_dst,
                    selection,
                    stop,
                    sniff,
                    metrics,
                    &password,
                )
                .await
            } else if selection.proxy.net == "grpc" {
                handle_trojan_grpc_tls_tcp_connection_async(
                    inbound,
                    peer,
                    original_dst,
                    selection,
                    stop,
                    sniff,
                    metrics,
                    &password,
                )
                .await
            } else {
                handle_trojan_tls_tcp_connection_async(
                    inbound,
                    peer,
                    original_dst,
                    selection,
                    stop,
                    sniff,
                    metrics,
                    &password,
                )
                .await
            }
        }
        ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls {
            password,
            inner_cipher,
            inner_password,
        } => {
            let password = password.clone();
            let inner_cipher = inner_cipher.clone();
            let inner_password = inner_password.clone();
            if selection.proxy.net != "websocket" {
                return Err(
                    "trojan inner Shadowsocks dispatcher admits WebSocket transport only"
                        .to_owned(),
                );
            }
            handle_trojan_websocket_inner_shadowsocks_tls_tcp_connection_async(
                inbound,
                peer,
                original_dst,
                selection,
                stop,
                sniff,
                metrics,
                &password,
                &inner_cipher,
                &inner_password,
            )
            .await
        }
        ResidentProxyProtocolPlan::AnyTlsTcpTls { auth } => {
            let auth = auth.clone();
            handle_anytls_tls_tcp_connection_async(
                inbound,
                peer,
                original_dst,
                selection,
                stop,
                sniff,
                metrics,
                &auth,
            )
            .await
        }
        _ => Err("frame TLS dispatcher received unsupported handler".to_owned()),
    }
}
