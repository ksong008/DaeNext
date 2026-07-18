use super::*;
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_frame_tls_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    anytls_owner_registry: Option<&AnyTlsOwnerRegistryHandle>,
    owner_deadline: Option<dae_runtime_control::AbsoluteDeadline>,
) -> Result<Value, String> {
    let wrapper = selection.proxy.execution_plan().wrapper;
    match &selection.proxy.handler {
        ResidentProxyProtocolPlan::TrojanTcpTls { password } => {
            let password = password.clone();
            if wrapper == ResidentStreamWrapperPlan::WebSocket {
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
            } else if wrapper == ResidentStreamWrapperPlan::HttpUpgrade {
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
            } else if wrapper == ResidentStreamWrapperPlan::Grpc {
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
            if wrapper != ResidentStreamWrapperPlan::WebSocket {
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
        ResidentProxyProtocolPlan::AnyTlsTcpTls { .. } => {
            handle_anytls_tls_tcp_connection_async(
                inbound,
                peer,
                original_dst,
                selection,
                stop,
                sniff,
                metrics,
                anytls_owner_registry,
                owner_deadline,
            )
            .await
        }
        _ => Err("frame TLS dispatcher received unsupported handler".to_owned()),
    }
}
