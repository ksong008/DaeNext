use super::*;

pub async fn handle_shadowsocks_stream_proxy_async(
    mut inbound: TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    mut sniff: TcpSniffReport,
    metrics: Arc<ResidentDataplaneMetrics>,
) -> Result<Value, String> {
    match &selection.proxy.handler {
        ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
            cipher,
            password,
            salt_len,
        } => {
            let cipher = cipher.clone();
            let password = password.clone();
            let salt_len = *salt_len;
            handle_shadowsocks_proxy_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                stop,
                &mut sniff,
                &metrics,
                &cipher,
                &password,
                salt_len,
            )
            .await
        }
        ResidentProxyProtocolPlan::Shadowsocks2022Tcp {
            cipher,
            password,
            salt_len,
            ..
        } => {
            let cipher = cipher.clone();
            let password = password.clone();
            let salt_len = *salt_len;
            handle_shadowsocks_2022_proxy_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                stop,
                &mut sniff,
                &metrics,
                &cipher,
                &password,
                salt_len,
            )
            .await
        }
        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp {
            cipher,
            password,
            salt_len,
            host,
            path,
        } => {
            let cipher = cipher.clone();
            let password = password.clone();
            let salt_len = *salt_len;
            let host = host.clone();
            let path = path.clone();
            handle_shadowsocks_simple_obfs_http_proxy_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                stop,
                &mut sniff,
                &metrics,
                &cipher,
                &password,
                salt_len,
                &host,
                &path,
            )
            .await
        }
        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp {
            cipher,
            password,
            salt_len,
            host,
        } => {
            let cipher = cipher.clone();
            let password = password.clone();
            let salt_len = *salt_len;
            let host = host.clone();
            handle_shadowsocks_simple_obfs_tls_proxy_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                stop,
                &mut sniff,
                &metrics,
                &cipher,
                &password,
                salt_len,
                &host,
            )
            .await
        }
        ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp {
            cipher,
            password,
            salt_len,
            host,
            path,
        } => {
            let cipher = cipher.clone();
            let password = password.clone();
            let salt_len = *salt_len;
            let host = host.clone();
            let path = path.clone();
            handle_shadowsocks_2022_simple_obfs_http_proxy_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                stop,
                &mut sniff,
                &metrics,
                &cipher,
                &password,
                salt_len,
                &host,
                &path,
            )
            .await
        }
        ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp {
            cipher,
            password,
            salt_len,
            host,
            path,
        } => {
            let cipher = cipher.clone();
            let password = password.clone();
            let salt_len = *salt_len;
            let host = host.clone();
            let path = path.clone();
            handle_shadowsocks_v2ray_plugin_tls_ws_proxy_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                stop,
                &mut sniff,
                &metrics,
                &cipher,
                &password,
                salt_len,
                &host,
                &path,
            )
            .await
        }
        ResidentProxyProtocolPlan::ShadowsocksRHttpSimpleTcp {
            cipher,
            password,
            obfs_host,
            obfs_port,
        } => {
            let cipher = cipher.clone();
            let password = password.clone();
            let obfs_host = obfs_host.clone();
            let obfs_port = *obfs_port;
            handle_shadowsocksr_http_simple_proxy_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                stop,
                &mut sniff,
                &metrics,
                &cipher,
                &password,
                &obfs_host,
                obfs_port,
            )
            .await
        }
        handler => Err(format!(
            "resident Shadowsocks TCP dispatcher received incompatible handler {handler:?}"
        )),
    }
}
