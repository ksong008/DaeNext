use super::*;
pub(crate) fn http_content_length(head: &[u8]) -> Result<usize, String> {
    let text =
        std::str::from_utf8(head).map_err(|err| format!("Meek response head utf8: {err}"))?;
    for line in text.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return value
                .trim()
                .parse::<usize>()
                .map_err(|err| format!("parse Meek response Content-Length: {err}"));
        }
    }
    Ok(0)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_vless_grpc_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let client =
        open_async_vless_tls_client_with_flow(&selection.proxy, selection.mark, selection.mptcp)
            .await?;
    let tls_underlay = async_tls_underlay_name(&client);
    let key = selection.proxy.vless_key()?;
    let request = packet::first_write_bytes(
        &key,
        &selection.proxy.flow,
        "tcp",
        &selection.route.dial_target,
        false,
        &sniff.payload,
    )
    .map_err(|err| format!("build VLESS gRPC TCP request: {err}"))?;
    let (mut h2_send, mut h2_recv, connection_task) =
        open_grpc_h2_stream(client, &selection.proxy, &request).await?;
    let mut initial_stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        initial_stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }

    let result = relay_tcp_over_grpc_h2(
        inbound,
        &mut h2_send,
        &mut h2_recv,
        stop,
        initial_stats,
        metrics,
        true,
    )
    .await;
    connection_task.abort();
    result
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "vless",
                &stats,
                "async-proxy-grpc-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("grpc");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-grpc-tls",
                "vless",
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
                "vless",
                &err,
                "async-proxy-grpc-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("grpc");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-grpc-tls",
                "vless",
                Some(tls_underlay),
                None,
            );
            Ok::<Value, String>(event)
        })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_vless_xhttp_h2_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let key = selection.proxy.vless_key()?;
    let XhttpPacketUpParts {
        session_id,
        mut upload,
        mut download,
        upload_underlay,
        upload_http_version,
        download_separate,
    } = open_xhttp_packet_up_parts(&selection.proxy, selection.mark, selection.mptcp).await?;
    let executor_label = match upload_http_version {
        ResidentXhttpHttpVersion::H1 => "async-proxy-xhttp-h1-tls",
        ResidentXhttpHttpVersion::H2 => "async-proxy-xhttp-h2-tls",
        ResidentXhttpHttpVersion::H3 => "async-proxy-xhttp-h3-tls",
    };
    let xhttp_alpn = upload_http_version.alpn_label();
    let request = packet::first_write_bytes(
        &key,
        &selection.proxy.flow,
        "tcp",
        &selection.route.dial_target,
        false,
        &sniff.payload,
    )
    .map_err(|err| format!("build VLESS xHTTP TCP request: {err}"))?;

    let mut initial_stats = DirectTcpRelayStats::default();
    initial_stats.client_to_direct += sniff.payload.len();
    if !sniff.payload.is_empty() {
        metrics.add_upload(sniff.payload.len());
    }
    let result = async {
        let mut seq = 0_u64;
        send_xhttp_packet_up_request(&mut upload, &session_id, seq, Bytes::from(request)).await?;
        seq = seq.saturating_add(1);
        relay_tcp_over_xhttp_packet_up(
            inbound,
            &mut upload,
            &mut download,
            &session_id,
            seq,
            stop,
            initial_stats,
            metrics,
        )
        .await
    }
    .await;
    close_xhttp_download_client(download).await;
    close_xhttp_upload_client(upload).await;

    result
        .map(|stats| {
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "vless",
                &stats,
                executor_label,
            );
            event["tls_underlay"] = json!(upload_underlay);
            event["stream_wrapper"] = json!("xhttp");
            event["xhttp_mode"] = json!("packet-up");
            event["xhttp_alpn"] = json!(xhttp_alpn);
            event["xhttp_download_separate"] = json!(download_separate);
            append_proxy_tcp_execution_fields(
                &mut event,
                executor_label,
                "vless",
                Some(upload_underlay),
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
                "vless",
                &err,
                executor_label,
            );
            event["tls_underlay"] = json!(upload_underlay);
            event["stream_wrapper"] = json!("xhttp");
            event["xhttp_mode"] = json!("packet-up");
            event["xhttp_alpn"] = json!(xhttp_alpn);
            event["xhttp_download_separate"] = json!(download_separate);
            append_proxy_tcp_execution_fields(
                &mut event,
                executor_label,
                "vless",
                Some(upload_underlay),
                None,
            );
            Ok::<Value, String>(event)
        })
}

pub(crate) async fn handle_resident_proxy_tcp_connection_async(
    mut inbound: TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: TcpSniffReport,
    metrics: Arc<ResidentDataplaneMetrics>,
) -> Result<Value, String> {
    if let ResidentProxyProtocolPlan::VmessAeadTcp { id } = &selection.proxy.handler
        && selection.proxy.net == "tcp"
        && selection.proxy.tls == "none"
    {
        let id = id.clone();
        return handle_vmess_proxy_tcp_connection_async(
            &mut inbound,
            peer,
            original_dst,
            selection,
            stop,
            &sniff,
            &metrics,
            &id,
        )
        .await;
    }
    if let ResidentProxyProtocolPlan::VmessAeadTcp { id } = &selection.proxy.handler
        && selection.proxy.net == "websocket"
        && selection.proxy.tls != "tls"
    {
        let id = id.clone();
        return handle_vmess_websocket_proxy_tcp_connection_async(
            &mut inbound,
            peer,
            original_dst,
            selection,
            stop,
            &sniff,
            &metrics,
            &id,
        )
        .await;
    }
    if let ResidentProxyProtocolPlan::VmessAeadTcp { id } = &selection.proxy.handler
        && selection.proxy.net == "httpupgrade"
        && selection.proxy.tls != "tls"
    {
        let id = id.clone();
        return handle_vmess_httpupgrade_proxy_tcp_connection_async(
            &mut inbound,
            peer,
            original_dst,
            selection,
            stop,
            &sniff,
            &metrics,
            &id,
        )
        .await;
    }
    if let ResidentProxyProtocolPlan::VmessAeadTcp { id } = &selection.proxy.handler
        && selection.proxy.net == "grpc"
    {
        let id = id.clone();
        return handle_vmess_grpc_proxy_tcp_connection_async(
            &mut inbound,
            peer,
            original_dst,
            selection,
            stop,
            &sniff,
            &metrics,
            &id,
        )
        .await;
    }
    if let ResidentProxyProtocolPlan::VmessAeadTcp { id } = &selection.proxy.handler
        && selection.proxy.net == "websocket"
        && selection.proxy.tls == "tls"
    {
        let id = id.clone();
        return handle_vmess_websocket_tls_proxy_tcp_connection_async(
            &mut inbound,
            peer,
            original_dst,
            selection,
            stop,
            &sniff,
            &metrics,
            &id,
        )
        .await;
    }
    if let ResidentProxyProtocolPlan::VmessAeadTcp { id } = &selection.proxy.handler
        && selection.proxy.net == "httpupgrade"
        && selection.proxy.tls == "tls"
    {
        let id = id.clone();
        return handle_vmess_httpupgrade_tls_proxy_tcp_connection_async(
            &mut inbound,
            peer,
            original_dst,
            selection,
            stop,
            &sniff,
            &metrics,
            &id,
        )
        .await;
    }
    if let ResidentProxyProtocolPlan::Socks5Tcp { username, password } = &selection.proxy.handler {
        let username = username.clone();
        let password = password.clone();
        return handle_socks5_proxy_tcp_connection_async(
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
        .await;
    }
    if let ResidentProxyProtocolPlan::HttpProxyTcp {
        username,
        password,
        transport,
        transport_host,
        transport_path,
    } = &selection.proxy.handler
        && selection.proxy.tls == "none"
    {
        let username = username.clone();
        let password = password.clone();
        let transport = *transport;
        let transport_host = transport_host.clone();
        let transport_path = transport_path.clone();
        return handle_http_proxy_tcp_connection_async(
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
        .await;
    }
    if let ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
        cipher,
        password,
        salt_len,
    } = &selection.proxy.handler
    {
        let cipher = cipher.clone();
        let password = password.clone();
        let salt_len = *salt_len;
        return handle_shadowsocks_proxy_tcp_connection_async(
            &mut inbound,
            peer,
            original_dst,
            selection,
            stop,
            &sniff,
            &metrics,
            &cipher,
            &password,
            salt_len,
        )
        .await;
    }
    if let ResidentProxyProtocolPlan::Shadowsocks2022Tcp {
        cipher,
        password,
        salt_len,
        ..
    } = &selection.proxy.handler
    {
        let cipher = cipher.clone();
        let password = password.clone();
        let salt_len = *salt_len;
        return handle_shadowsocks_2022_proxy_tcp_connection_async(
            &mut inbound,
            peer,
            original_dst,
            selection,
            stop,
            &sniff,
            &metrics,
            &cipher,
            &password,
            salt_len,
        )
        .await;
    }
    if let ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp {
        cipher,
        password,
        salt_len,
        host,
        path,
    } = &selection.proxy.handler
    {
        let cipher = cipher.clone();
        let password = password.clone();
        let salt_len = *salt_len;
        let host = host.clone();
        let path = path.clone();
        return handle_shadowsocks_simple_obfs_http_proxy_tcp_connection_async(
            &mut inbound,
            peer,
            original_dst,
            selection,
            stop,
            &sniff,
            &metrics,
            &cipher,
            &password,
            salt_len,
            &host,
            &path,
        )
        .await;
    }
    if let ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp {
        cipher,
        password,
        salt_len,
        host,
    } = &selection.proxy.handler
    {
        let cipher = cipher.clone();
        let password = password.clone();
        let salt_len = *salt_len;
        let host = host.clone();
        return handle_shadowsocks_simple_obfs_tls_proxy_tcp_connection_async(
            &mut inbound,
            peer,
            original_dst,
            selection,
            stop,
            &sniff,
            &metrics,
            &cipher,
            &password,
            salt_len,
            &host,
        )
        .await;
    }
    if let ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp {
        cipher,
        password,
        salt_len,
        host,
        path,
    } = &selection.proxy.handler
    {
        let cipher = cipher.clone();
        let password = password.clone();
        let salt_len = *salt_len;
        let host = host.clone();
        let path = path.clone();
        return handle_shadowsocks_2022_simple_obfs_http_proxy_tcp_connection_async(
            &mut inbound,
            peer,
            original_dst,
            selection,
            stop,
            &sniff,
            &metrics,
            &cipher,
            &password,
            salt_len,
            &host,
            &path,
        )
        .await;
    }
    if let ResidentProxyProtocolPlan::HttpProxyTcp {
        username,
        password,
        transport,
        transport_host,
        transport_path,
    } = &selection.proxy.handler
        && selection.proxy.tls == "tls"
    {
        let username = username.clone();
        let password = password.clone();
        let transport = *transport;
        let transport_host = transport_host.clone();
        let transport_path = transport_path.clone();
        return handle_https_proxy_tcp_connection_async(
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
        .await;
    }
    if let ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp {
        cipher,
        password,
        salt_len,
        host,
        path,
    } = &selection.proxy.handler
    {
        let cipher = cipher.clone();
        let password = password.clone();
        let salt_len = *salt_len;
        let host = host.clone();
        let path = path.clone();
        return handle_shadowsocks_v2ray_plugin_tls_ws_proxy_tcp_connection_async(
            &mut inbound,
            peer,
            original_dst,
            selection,
            stop,
            &sniff,
            &metrics,
            &cipher,
            &password,
            salt_len,
            &host,
            &path,
        )
        .await;
    }
    if let ResidentProxyProtocolPlan::ShadowsocksRHttpSimpleTcp {
        cipher,
        password,
        obfs_host,
        obfs_port,
    } = &selection.proxy.handler
    {
        let cipher = cipher.clone();
        let password = password.clone();
        let obfs_host = obfs_host.clone();
        let obfs_port = *obfs_port;
        return handle_shadowsocksr_http_simple_proxy_tcp_connection_async(
            &mut inbound,
            peer,
            original_dst,
            selection,
            stop,
            &sniff,
            &metrics,
            &cipher,
            &password,
            &obfs_host,
            obfs_port,
        )
        .await;
    }
    Err(format!(
        "resident async TCP dispatcher has no handler for protocol {} net {} tls {}",
        selection.proxy.protocol, selection.proxy.net, selection.proxy.tls
    ))
}
