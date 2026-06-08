use super::*;
pub(crate) fn handle_resident_proxy_tcp_connection(
    inbound: &mut TcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: &AtomicBool,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    match &selection.proxy.handler {
        ResidentProxyProtocolPlan::Socks5Tcp { username, password } => {
            handle_socks5_proxy_tcp_connection(
                inbound,
                peer,
                original_dst,
                &selection,
                stop,
                sniff,
                metrics,
                username,
                password,
            )
        }
        ResidentProxyProtocolPlan::HttpProxyTcp {
            username,
            password,
            transport,
            transport_host,
            transport_path,
        } => handle_http_proxy_tcp_connection(
            inbound,
            peer,
            original_dst,
            &selection,
            stop,
            sniff,
            metrics,
            username,
            password,
            *transport,
            transport_host,
            transport_path,
        ),
        ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
            cipher,
            password,
            salt_len,
        } => handle_shadowsocks_proxy_tcp_connection(
            inbound,
            peer,
            original_dst,
            &selection,
            stop,
            sniff,
            metrics,
            cipher,
            password,
            *salt_len,
        ),
        ResidentProxyProtocolPlan::Shadowsocks2022Tcp {
            cipher,
            password,
            salt_len,
            ..
        } => handle_shadowsocks_2022_proxy_tcp_connection(
            inbound,
            peer,
            original_dst,
            &selection,
            stop,
            sniff,
            metrics,
            cipher,
            password,
            *salt_len,
        ),
        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp {
            cipher,
            password,
            salt_len,
            host,
            path,
        } => handle_shadowsocks_simple_obfs_http_proxy_tcp_connection(
            inbound,
            peer,
            original_dst,
            &selection,
            stop,
            sniff,
            metrics,
            cipher,
            password,
            *salt_len,
            host,
            path,
        ),
        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp {
            cipher,
            password,
            salt_len,
            host,
        } => handle_shadowsocks_simple_obfs_tls_proxy_tcp_connection(
            inbound,
            peer,
            original_dst,
            &selection,
            stop,
            sniff,
            metrics,
            cipher,
            password,
            *salt_len,
            host,
        ),
        ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp { .. } => Err(
            "resident Shadowsocks v2ray-plugin TLS/WebSocket handler must use async TLS dispatcher"
                .to_owned(),
        ),
        ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp {
            cipher,
            password,
            salt_len,
            host,
            path,
        } => handle_shadowsocks_2022_simple_obfs_http_proxy_tcp_connection(
            inbound,
            peer,
            original_dst,
            &selection,
            stop,
            sniff,
            metrics,
            cipher,
            password,
            *salt_len,
            host,
            path,
        ),
        ResidentProxyProtocolPlan::ShadowsocksRHttpSimpleTcp {
            cipher,
            password,
            obfs_host,
            obfs_port,
        } => handle_shadowsocksr_http_simple_proxy_tcp_connection(
            inbound,
            peer,
            original_dst,
            &selection,
            stop,
            sniff,
            metrics,
            cipher,
            password,
            obfs_host,
            *obfs_port,
        ),
        ResidentProxyProtocolPlan::VmessAeadTcp { id } => {
            if selection.proxy.net == "websocket" {
                handle_vmess_websocket_proxy_tcp_connection(
                    inbound,
                    peer,
                    original_dst,
                    &selection,
                    stop,
                    sniff,
                    metrics,
                    id,
                )
            } else if selection.proxy.net == "httpupgrade" {
                handle_vmess_httpupgrade_proxy_tcp_connection(
                    inbound,
                    peer,
                    original_dst,
                    &selection,
                    stop,
                    sniff,
                    metrics,
                    id,
                )
            } else if selection.proxy.net == "grpc" {
                Err("resident VMess gRPC handler must use async TLS HTTP/2 dispatcher".to_owned())
            } else {
                handle_vmess_proxy_tcp_connection(
                    inbound,
                    peer,
                    original_dst,
                    &selection,
                    stop,
                    sniff,
                    metrics,
                    id,
                )
            }
        }
        ResidentProxyProtocolPlan::VlessVisionTcpTls { .. } => Err(
            "resident proxy dispatcher received VLESS handler; use VLESS TLS dispatcher".to_owned(),
        ),
        ResidentProxyProtocolPlan::TrojanTcpTls { .. } => Err(
            "resident proxy dispatcher received generic TLS handler; use TLS dispatcher".to_owned(),
        ),
        ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls { .. } => Err(
            "resident proxy dispatcher received inner-encryption TLS handler; use TLS dispatcher"
                .to_owned(),
        ),
        ResidentProxyProtocolPlan::AnyTlsTcpTls { .. } => Err(
            "resident proxy dispatcher received frame TLS handler; use TLS dispatcher".to_owned(),
        ),
        ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. } => {
            Err("resident proxy dispatcher received QUIC handler; use QUIC dispatcher".to_owned())
        }
        ResidentProxyProtocolPlan::TuicQuicTcp { .. } => {
            Err("resident proxy dispatcher received QUIC handler; use QUIC dispatcher".to_owned())
        }
        ResidentProxyProtocolPlan::JuicityQuicTcp { .. } => {
            Err("resident proxy dispatcher received QUIC handler; use QUIC dispatcher".to_owned())
        }
    }
}
pub(crate) async fn handle_frame_tls_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
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
