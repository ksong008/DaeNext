use super::*;

pub(super) async fn handle_vmess_stream_proxy_async(
    mut inbound: TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    mut sniff: TcpSniffReport,
    metrics: Arc<ResidentDataplaneMetrics>,
) -> Result<Value, String> {
    let execution = selection.proxy.execution_plan();
    let id = match &selection.proxy.handler {
        ResidentProxyProtocolPlan::VmessAeadTcp { id } => id.clone(),
        handler => {
            return Err(format!(
                "resident VMess TCP dispatcher received incompatible handler {handler:?}"
            ));
        }
    };

    match (execution.wrapper, execution.security) {
        (ResidentStreamWrapperPlan::None, ResidentSecurityUnderlayPlan::None) => {
            handle_vmess_proxy_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                stop,
                &mut sniff,
                &metrics,
                &id,
            )
            .await
        }
        (ResidentStreamWrapperPlan::None, security) if security.is_standard_tls_stream() => {
            handle_vmess_tls_proxy_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                stop,
                &mut sniff,
                &metrics,
                &id,
            )
            .await
        }
        (ResidentStreamWrapperPlan::WebSocket, ResidentSecurityUnderlayPlan::None) => {
            handle_vmess_websocket_proxy_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                stop,
                &mut sniff,
                &metrics,
                &id,
            )
            .await
        }
        (ResidentStreamWrapperPlan::HttpUpgrade, ResidentSecurityUnderlayPlan::None) => {
            handle_vmess_httpupgrade_proxy_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                stop,
                &mut sniff,
                &metrics,
                &id,
            )
            .await
        }
        (ResidentStreamWrapperPlan::Grpc, security) if security.is_standard_tls_stream() => {
            handle_vmess_grpc_proxy_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                stop,
                &mut sniff,
                &metrics,
                &id,
            )
            .await
        }
        (ResidentStreamWrapperPlan::H2, security) if security.is_standard_tls_stream() => {
            handle_vmess_h2_proxy_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                stop,
                &mut sniff,
                &metrics,
                &id,
            )
            .await
        }
        (ResidentStreamWrapperPlan::WebSocket, security) if security.is_standard_tls_stream() => {
            handle_vmess_websocket_tls_proxy_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                stop,
                &mut sniff,
                &metrics,
                &id,
            )
            .await
        }
        (ResidentStreamWrapperPlan::HttpUpgrade, security) if security.is_standard_tls_stream() => {
            handle_vmess_httpupgrade_tls_proxy_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                stop,
                &mut sniff,
                &metrics,
                &id,
            )
            .await
        }
        (wrapper, security) => Err(format!(
            "resident VMess TCP dispatcher rejects wrapper {wrapper:?} security {security:?}"
        )),
    }
}
