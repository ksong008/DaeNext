use super::*;
pub(crate) fn handle_proxy_tcp_connection(
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

pub(crate) async fn handle_proxy_tcp_connection_async(
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
pub(crate) async fn handle_vless_websocket_tcp_connection_async(
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
pub(crate) async fn handle_vless_httpupgrade_tcp_connection_async(
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
pub(crate) async fn handle_vless_meek_tcp_connection_async(
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
