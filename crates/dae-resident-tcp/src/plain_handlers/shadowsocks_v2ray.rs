use super::*;
#[allow(clippy::too_many_arguments)]
pub async fn handle_shadowsocks_v2ray_plugin_tls_ws_proxy_tcp_connection_async(
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
    host: &str,
    path: &str,
) -> Result<Value, String> {
    let mut client =
        open_async_resident_tls_client_with_binding(&selection.proxy, selection.mptcp).await?;
    let tls_underlay = async_resident_tls_underlay_name(&client);
    let options = HttpUpgradeOptions::new(host, path);
    let ws_leftover = websocket_handshake_over_resident_tls_async(&mut client, &options).await?;
    let initial_payload = sniff.take_payload();
    let stats = relay_tcp_over_shadowsocks_v2ray_plugin_tls_ws(
        inbound,
        &mut client,
        stop,
        &selection.route.dial_target,
        cipher,
        password,
        salt_len,
        initial_payload,
        metrics,
        ws_leftover,
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
                "plugin-wrapper-tls-websocket-aead",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["plugin_wrapper"] = json!("v2ray-plugin-tls-websocket");
            event["stream_wrapper"] = json!("websocket");
            append_proxy_tcp_execution_fields(
                &mut event,
                "plugin-wrapper-tls-websocket-aead",
                "shadowsocks",
                Some(tls_underlay),
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
                "plugin-wrapper-tls-websocket-aead",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["plugin_wrapper"] = json!("v2ray-plugin-tls-websocket");
            event["stream_wrapper"] = json!("websocket");
            append_proxy_tcp_execution_fields(
                &mut event,
                "plugin-wrapper-tls-websocket-aead",
                "shadowsocks",
                Some(tls_underlay),
                None,
            );
            Ok::<Value, String>(event)
        })
}
