fn handle_proxy_tcp_connection(
    inbound: &mut TcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: &AtomicBool,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let mut client = open_vless_tls_client(&selection.proxy)?;
    let tls_underlay = tls_underlay_name(&client);
    client.set_nonblocking(true)?;
    let request = packet::first_write_bytes(
        &selection.proxy.vless_key()?,
        &selection.proxy.flow,
        "tcp",
        &selection.route.dial_target,
        false,
        &[],
    )
    .map_err(|err| format!("build VLESS TCP request: {err}"))?;
    client
        .queue_plain(&request, "queue VLESS TCP request")
        .map_err(|err| err.to_string())?;
    relay_tcp_over_vless_tls(
        inbound,
        &mut client,
        stop,
        &selection.proxy.flow,
        selection.proxy.vless_key()?,
        &sniff.payload,
        metrics,
    )
    .map(|stats| {
        proxy_tcp_finished_event(
            peer,
            original_dst,
            &selection,
            sniff,
            tls_underlay,
            &stats,
            "per-connection-thread-legacy",
        )
    })
    .or_else(|err| {
        Ok::<Value, String>(proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            tls_underlay,
            &err,
            "per-connection-thread-legacy",
        ))
    })
}

async fn handle_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    if selection.proxy.net == "websocket" {
        return handle_vless_websocket_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            sniff,
            metrics,
        )
        .await;
    }
    if selection.proxy.net == "httpupgrade" {
        return handle_vless_httpupgrade_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            sniff,
            metrics,
        )
        .await;
    }
    if selection.proxy.net == "grpc" {
        return handle_vless_grpc_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            sniff,
            metrics,
        )
        .await;
    }
    if selection.proxy.net == "meek" {
        return handle_vless_meek_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            sniff,
            metrics,
        )
        .await;
    }
    if selection.proxy.net == "xhttp" {
        return handle_vless_xhttp_h2_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            sniff,
            metrics,
        )
        .await;
    }
    let mut client = open_async_vless_tls_client(&selection.proxy).await?;
    let tls_underlay = async_tls_underlay_name(&client);
    let key = selection.proxy.vless_key()?;
    let request = packet::first_write_bytes(
        &key,
        &selection.proxy.flow,
        "tcp",
        &selection.route.dial_target,
        false,
        &[],
    )
    .map_err(|err| format!("build VLESS TCP request: {err}"))?;
    client
        .write_plain_all(&request, "write VLESS TCP request")
        .await?;
    relay_tcp_over_vless_tls_async(
        inbound,
        &mut client,
        stop,
        &selection.proxy.flow,
        key,
        &sniff.payload,
        metrics,
    )
    .await
    .map(|stats| {
        let event = proxy_tcp_finished_event(
            peer,
            original_dst,
            &selection,
            sniff,
            tls_underlay,
            &stats,
            "async-proxy-tls",
        );
        event
    })
    .or_else(|err| {
        let event = proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            tls_underlay,
            &err,
            "async-proxy-tls",
        );
        Ok::<Value, String>(event)
    })
}

#[allow(clippy::too_many_arguments)]
async fn handle_vless_websocket_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let mut client = open_async_vless_tls_client(&selection.proxy).await?;
    let tls_underlay = async_tls_underlay_name(&client);
    let key = selection.proxy.vless_key()?;
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    websocket_handshake_over_resident_tls_async(&mut client, &options).await?;
    let request = packet::first_write_bytes(
        &key,
        &selection.proxy.flow,
        "tcp",
        &selection.route.dial_target,
        false,
        &sniff.payload,
    )
    .map_err(|err| format!("build VLESS WebSocket TCP request: {err}"))?;
    write_websocket_binary_frame_over_resident_tls_async(
        &mut client,
        &request,
        "write VLESS websocket request",
    )
    .await?;
    if !sniff.payload.is_empty() {
        metrics.add_upload(sniff.payload.len());
    }
    relay_tcp_over_vless_websocket_tls_async(
        inbound,
        &mut client,
        stop,
        sniff.payload.len(),
        metrics,
    )
    .await
    .map(|stats| {
        let mut event = proxy_tcp_finished_event(
            peer,
            original_dst,
            &selection,
            sniff,
            tls_underlay,
            &stats,
            "async-proxy-websocket-tls",
        );
        event["stream_wrapper"] = json!("websocket");
        event
    })
    .or_else(|err| {
        let mut event = proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            tls_underlay,
            &err,
            "async-proxy-websocket-tls",
        );
        event["stream_wrapper"] = json!("websocket");
        Ok::<Value, String>(event)
    })
}

#[allow(clippy::too_many_arguments)]
async fn handle_vless_httpupgrade_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let mut client = open_async_vless_tls_client(&selection.proxy).await?;
    let tls_underlay = async_tls_underlay_name(&client);
    let key = selection.proxy.vless_key()?;
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    httpupgrade_handshake_over_resident_tls_async(&mut client, &options).await?;
    let request = packet::first_write_bytes(
        &key,
        &selection.proxy.flow,
        "tcp",
        &selection.route.dial_target,
        false,
        &[],
    )
    .map_err(|err| format!("build VLESS HTTP Upgrade TCP request: {err}"))?;
    client
        .write_plain_all(&request, "write VLESS HTTP Upgrade TCP request")
        .await?;
    relay_tcp_over_vless_tls_async(
        inbound,
        &mut client,
        stop,
        &selection.proxy.flow,
        key,
        &sniff.payload,
        metrics,
    )
    .await
    .map(|stats| {
        let mut event = proxy_tcp_finished_event(
            peer,
            original_dst,
            &selection,
            sniff,
            tls_underlay,
            &stats,
            "async-proxy-httpupgrade-tls",
        );
        event["stream_wrapper"] = json!("httpupgrade");
        event
    })
    .or_else(|err| {
        let mut event = proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            tls_underlay,
            &err,
            "async-proxy-httpupgrade-tls",
        );
        event["stream_wrapper"] = json!("httpupgrade");
        Ok::<Value, String>(event)
    })
}

#[allow(clippy::too_many_arguments)]
async fn handle_vless_meek_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let tls_underlay = if selection.proxy.utls_fingerprint.is_some() {
        "boringssl"
    } else {
        "rustls"
    };
    let key = selection.proxy.vless_key()?;
    let options = meek_options_from_proxy(&selection, peer, original_dst);
    let first_payload = packet::first_write_bytes(
        &key,
        "",
        "tcp",
        &selection.route.dial_target,
        false,
        &sniff.payload,
    )
    .map_err(|err| format!("build VLESS Meek TCP request: {err}"))?;
    let mut stats = DirectTcpRelayStats::default();
    if !sniff.payload.is_empty() {
        stats.client_to_direct += sniff.payload.len();
        metrics.add_upload(sniff.payload.len());
    }
    let mut stripper = VlessResponseStripper::default();
    let mut next_body = Some(first_payload);
    let mut inbound_closed = false;
    let mut last_activity = Instant::now();
    let mut empty_poll_count = 0_usize;

    while !stop.load(Ordering::Relaxed) {
        let body = if let Some(body) = next_body.take() {
            body
        } else {
            let mut buf = [0_u8; 16 * 1024];
            match time::timeout(Duration::from_millis(150), inbound.read(&mut buf)).await {
                Ok(Ok(0)) => {
                    inbound_closed = true;
                    Vec::new()
                }
                Ok(Ok(read)) => {
                    stats.client_to_direct += read;
                    metrics.add_upload(read);
                    last_activity = Instant::now();
                    empty_poll_count = 0;
                    buf[..read].to_vec()
                }
                Ok(Err(err)) if is_graceful_stream_close_error(&err) => {
                    inbound_closed = true;
                    Vec::new()
                }
                Ok(Err(err)) => return Err(format!("read inbound TCP for Meek relay: {err}")),
                Err(_) => Vec::new(),
            }
        };

        if body.is_empty() {
            empty_poll_count = empty_poll_count.saturating_add(1);
        }
        let response = meek_round_trip_async(&selection.proxy, &options, &body).await?;
        let response_payload = stripper.consume(&response)?;
        if !response_payload.is_empty() {
            inbound
                .write_all(&response_payload)
                .await
                .map_err(|err| format!("write Meek response payload to client: {err}"))?;
            stats.direct_to_client += response_payload.len();
            metrics.add_download(response_payload.len());
            last_activity = Instant::now();
            empty_poll_count = 0;
        }
        if inbound_closed && response_payload.is_empty() {
            break;
        }
        if empty_poll_count >= 3 && last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
            break;
        }
    }

    let mut event = generic_proxy_tcp_finished_event(
        peer,
        original_dst,
        &selection,
        sniff,
        "vless",
        &stats,
        "async-proxy-meek-tls",
    );
    event["tls_underlay"] = json!(tls_underlay);
    event["stream_wrapper"] = json!("meek");
    event["meek_polling"] = json!(true);
    append_proxy_tcp_execution_fields(
        &mut event,
        "async-proxy-meek-tls",
        "vless",
        Some(tls_underlay),
        None,
    );
    Ok(event)
}

fn meek_options_from_proxy(
    selection: &TcpProxySelection,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
) -> MeekRoundTripOptions {
    MeekRoundTripOptions {
        url: format!(
            "https://{}{}",
            selection.proxy.stream_host, selection.proxy.stream_path
        ),
        host: selection.proxy.stream_host.clone(),
        path: selection.proxy.stream_path.clone(),
        session_tag: format!("{}|{}|{}", selection.proxy.graph_id, peer, original_dst).into_bytes(),
    }
}

async fn meek_round_trip_async(
    proxy: &ResidentProxyPlan,
    options: &MeekRoundTripOptions,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    let mut client = open_async_resident_tls_client(proxy).await?;
    let request = meek_http_request(options, body);
    client
        .write_plain_all(&request, "write Meek polling request")
        .await?;
    let response = read_meek_http_response_body_async(&mut client).await;
    client.shutdown().await;
    response
}

async fn read_meek_http_response_body_async(
    client: &mut AsyncResidentTlsClient,
) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    let mut buf = [0_u8; 1024];
    let head_end = loop {
        let read = time::timeout(RESIDENT_CONNECT_TIMEOUT, client.read_plain(&mut buf))
            .await
            .map_err(|_| "read Meek response head timeout".to_owned())?
            .map_err(|err| format!("read Meek response head: {err}"))?;
        if read == 0 {
            return Err("Meek response closed before header".to_owned());
        }
        data.extend_from_slice(&buf[..read]);
        if let Some(index) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        if data.len() > 8192 {
            return Err("Meek response header too large".to_owned());
        }
    };
    let head = data[..head_end].to_vec();
    validate_http_status(&head, 200).map_err(|err| format!("validate Meek response: {err}"))?;
    let content_length = http_content_length(&head)?;
    let mut body = data[head_end..].to_vec();
    while body.len() < content_length {
        let read = time::timeout(RESIDENT_CONNECT_TIMEOUT, client.read_plain(&mut buf))
            .await
            .map_err(|_| "read Meek response body timeout".to_owned())?
            .map_err(|err| format!("read Meek response body: {err}"))?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&buf[..read]);
    }
    body.truncate(content_length);
    Ok(body)
}

fn http_content_length(head: &[u8]) -> Result<usize, String> {
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
async fn handle_vless_grpc_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let client = open_async_vless_tls_client(&selection.proxy).await?;
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
async fn handle_vless_xhttp_h2_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let client = open_async_vless_tls_client(&selection.proxy).await?;
    let tls_underlay = async_tls_underlay_name(&client);
    let key = selection.proxy.vless_key()?;
    let session_id = new_xhttp_session_id();
    let (mut h2_send, mut h2_recv, connection_task) =
        open_xhttp_h2_packet_up_session(client, &selection.proxy, &session_id).await?;
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
        send_xhttp_h2_packet_up_request(
            &mut h2_send,
            &selection.proxy,
            &session_id,
            seq,
            Bytes::from(request),
        )
        .await?;
        seq = seq.saturating_add(1);
        relay_tcp_over_xhttp_h2_packet_up(
            inbound,
            &mut h2_send,
            &mut h2_recv,
            &selection.proxy,
            &session_id,
            seq,
            stop,
            initial_stats,
            metrics,
        )
        .await
    }
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
                "async-proxy-xhttp-h2-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("xhttp");
            event["xhttp_mode"] = json!("packet-up");
            event["xhttp_alpn"] = json!("h2");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-xhttp-h2-tls",
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
                "async-proxy-xhttp-h2-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            event["stream_wrapper"] = json!("xhttp");
            event["xhttp_mode"] = json!("packet-up");
            event["xhttp_alpn"] = json!("h2");
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-xhttp-h2-tls",
                "vless",
                Some(tls_underlay),
                None,
            );
            Ok::<Value, String>(event)
        })
}

async fn handle_resident_proxy_tcp_connection_async(
    mut inbound: TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: TcpSniffReport,
    metrics: Arc<ResidentDataplaneMetrics>,
) -> Result<Value, String> {
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
    let mut inbound = inbound
        .into_std()
        .map_err(|err| format!("convert async inbound TCP to std for resident proxy: {err}"))?;
    tokio::task::spawn_blocking(move || {
        inbound
            .set_nonblocking(false)
            .map_err(|err| format!("set resident proxy inbound blocking: {err}"))?;
        handle_resident_proxy_tcp_connection(
            &mut inbound,
            peer,
            original_dst,
            selection,
            &stop,
            &sniff,
            &metrics,
        )
    })
    .await
    .map_err(|err| format!("join resident proxy task: {err}"))?
}
