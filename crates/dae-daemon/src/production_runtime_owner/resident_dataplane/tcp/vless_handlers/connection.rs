use super::*;
use crate::production_runtime_owner::resident_dataplane::acquire_vless_mux_logical_stream;
pub(crate) async fn handle_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    mut sniff: TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let execution = selection.proxy.execution_plan();
    if execution.wrapper == ResidentStreamWrapperPlan::Mux {
        return handle_vless_mux_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            &mut sniff,
            metrics,
        )
        .await;
    }
    if execution.wrapper == ResidentStreamWrapperPlan::WebSocket {
        return handle_vless_websocket_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            &mut sniff,
            metrics,
        )
        .await;
    }
    if execution.wrapper == ResidentStreamWrapperPlan::HttpUpgrade {
        return handle_vless_httpupgrade_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            &mut sniff,
            metrics,
        )
        .await;
    }
    if execution.wrapper == ResidentStreamWrapperPlan::Grpc {
        return handle_vless_grpc_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            &mut sniff,
            metrics,
        )
        .await;
    }
    if execution.wrapper == ResidentStreamWrapperPlan::H2 {
        return handle_vless_h2_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            &mut sniff,
            metrics,
        )
        .await;
    }
    if execution.wrapper == ResidentStreamWrapperPlan::Meek {
        return handle_vless_meek_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            &mut sniff,
            metrics,
        )
        .await;
    }
    if matches!(execution.wrapper, ResidentStreamWrapperPlan::Xhttp(_)) {
        return handle_vless_xhttp_h2_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            &mut sniff,
            metrics,
        )
        .await;
    }
    if execution.wrapper == ResidentStreamWrapperPlan::None
        && execution.security == ResidentSecurityUnderlayPlan::None
    {
        return handle_vless_plain_tcp_connection_async(
            inbound,
            peer,
            original_dst,
            selection,
            stop,
            &mut sniff,
            metrics,
        )
        .await;
    }
    if execution.wrapper != ResidentStreamWrapperPlan::None {
        return Err("materialized VLESS wrapper has no TCP executor".to_owned());
    }
    let mut client =
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
        &[],
    )
    .map_err(|err| format!("build VLESS TCP request: {err}"))?;
    client
        .write_plain_all(&request, "write VLESS TCP request")
        .await?;
    drop(request);
    let initial_payload = sniff.take_payload();
    relay_tcp_over_vless_tls_async(
        inbound,
        &mut client,
        stop,
        &selection.proxy.flow,
        key,
        initial_payload,
        metrics,
    )
    .await
    .map(|stats| {
        proxy_tcp_finished_event(
            peer,
            original_dst,
            &selection,
            &sniff,
            tls_underlay,
            &stats,
            "async-proxy-tls",
        )
    })
    .or_else(|err| {
        let event = proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            &sniff,
            tls_underlay,
            &err,
            "async-proxy-tls",
        );
        Ok::<Value, String>(event)
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_vless_plain_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let mut client =
        open_proxy_tcp_stream_async_with_flow(&selection.proxy, selection.mark, selection.mptcp)
            .await?;
    let key = selection.proxy.vless_key()?;
    let request = packet::first_write_bytes(
        &key,
        &selection.proxy.flow,
        "tcp",
        &selection.route.dial_target,
        false,
        &[],
    )
    .map_err(|err| format!("build VLESS plain TCP request: {err}"))?;
    client
        .write_all(&request)
        .await
        .map_err(|err| format!("write VLESS plain TCP request: {err}"))?;
    drop(request);
    let initial_payload = sniff.take_payload();
    relay_tcp_over_vless_plain_async(inbound, &mut client, stop, initial_payload, metrics)
        .await
        .map(|stats| {
            proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "none",
                &stats,
                "async-proxy-plain",
            )
        })
        .or_else(|err| {
            let event = proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "none",
                &err,
                "async-proxy-plain",
            );
            Ok::<Value, String>(event)
        })
}

pub(crate) async fn relay_tcp_over_vless_plain_async(
    inbound: &mut TokioTcpStream,
    proxy: &mut TokioTcpStream,
    stop: SharedResidentStopSignal,
    initial_payload: Vec<u8>,
    metrics: &ResidentDataplaneMetrics,
) -> Result<RelayStats, RelayError> {
    let mut stats = RelayStats::default();
    let mut stripper = VlessResponseStripper::default();
    let mut inbound_closed = false;
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut proxy_buf = [0_u8; 16 * 1024];
    let mut stop_listener = stop.listener();
    let idle_deadline = resident_relay_idle_deadline(RESIDENT_TCP_IDLE_TIMEOUT);
    let close_drain_deadline =
        resident_relay_idle_deadline(RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT);
    tokio::pin!(idle_deadline);
    tokio::pin!(close_drain_deadline);
    let mut close_drain_active = false;

    if !initial_payload.is_empty() {
        proxy.write_all(&initial_payload).await.map_err(|err| {
            RelayError::new(
                format!("write sniffed client payload to VLESS plain TCP: {err}"),
                &stats,
            )
        })?;
        stats.client_to_proxy += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }
    drop(initial_payload);

    loop {
        tokio::select! {
            _ = stop_listener.cancelled() => break,
            inbound_read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match inbound_read {
                    Ok(0) => {
                        inbound_closed = true;
                        let _ = proxy.shutdown().await;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                        reset_resident_relay_idle_deadline(
                            close_drain_deadline.as_mut(),
                            RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT,
                        );
                        close_drain_active = true;
                    }
                    Ok(read) => {
                        proxy
                            .write_all(&inbound_buf[..read])
                            .await
                            .map_err(|err| RelayError::new(format!("write client payload to VLESS plain TCP: {err}"), &stats))?;
                        stats.client_to_proxy += read;
                        metrics.add_upload(read);
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        let _ = proxy.shutdown().await;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                        reset_resident_relay_idle_deadline(
                            close_drain_deadline.as_mut(),
                            RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT,
                        );
                        close_drain_active = true;
                    }
                    Err(err) => {
                        return Err(RelayError::new(format!("read inbound TCP: {err}"), &stats));
                    }
                }
            }
            proxy_read = proxy.read(&mut proxy_buf) => {
                match proxy_read {
                    Ok(0) => break,
                    Ok(read) => {
                        let payload = stripper
                            .consume(&proxy_buf[..read])
                            .map_err(|err| RelayError::new(err, &stats))?;
                        stats.response_header_stripped = stripper.done;
                        if !payload.is_empty() {
                            inbound
                                .write_all(&payload)
                                .await
                                .map_err(|err| RelayError::new(format!("write VLESS plain TCP payload to client: {err}"), &stats))?;
                            stats.proxy_to_client += payload.len();
                            metrics.add_download(payload.len());
                        }
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                        if close_drain_active {
                            reset_resident_relay_idle_deadline(
                                close_drain_deadline.as_mut(),
                                RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT,
                            );
                        }
                    }
                    Err(err) => {
                        return Err(RelayError::new(format!("read VLESS plain TCP: {err}"), &stats));
                    }
                }
            }
            _ = &mut close_drain_deadline, if close_drain_active => break,
            _ = &mut idle_deadline => {
                return Err(RelayError::new("resident TCP relay idle timeout", &stats));
            }
        }
    }
    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_vless_mux_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let deadline =
        dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), RESIDENT_CONNECT_TIMEOUT);
    let mut logical = acquire_vless_mux_logical_stream(
        Arc::clone(&selection.proxy),
        selection.route.dial_target.clone(),
        deadline,
    )
    .await?;
    let tls_underlay = logical.tls_underlay();
    let mux_sid = logical.sid();
    let physical_instance_id = logical.physical_instance_id();
    let initial_payload = sniff.take_payload();
    relay_tcp_over_vless_mux_stream_async(inbound, &mut logical, stop, initial_payload, metrics)
        .await
        .map(|stats| {
            let mut event = proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                tls_underlay,
                &stats,
                "async-mux-tls",
            );
            event["stream_wrapper"] = json!("mux");
            event["packet_semantics"] = json!("multiplexed-stream");
            event["mux_sid"] = json!(mux_sid);
            event["mux_physical_instance_id"] = json!(physical_instance_id);
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
                "async-mux-tls",
            );
            event["stream_wrapper"] = json!("mux");
            event["packet_semantics"] = json!("multiplexed-stream");
            event["mux_sid"] = json!(mux_sid);
            event["mux_physical_instance_id"] = json!(physical_instance_id);
            Ok::<Value, String>(event)
        })
}

pub(crate) async fn relay_tcp_over_vless_mux_stream_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    logical: &mut (impl AsyncRead + AsyncWrite + Unpin),
    stop: SharedResidentStopSignal,
    initial_payload: Vec<u8>,
    metrics: &ResidentDataplaneMetrics,
) -> Result<RelayStats, RelayError> {
    let mut stats = RelayStats {
        response_header_stripped: true,
        ..RelayStats::default()
    };
    let mut inbound_closed = false;
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut logical_buf = [0_u8; 16 * 1024];
    let mut stop_listener = stop.listener();
    let idle_deadline = resident_relay_idle_deadline(RESIDENT_TCP_IDLE_TIMEOUT);
    let close_drain_deadline =
        resident_relay_idle_deadline(RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT);
    tokio::pin!(idle_deadline);
    tokio::pin!(close_drain_deadline);
    let mut close_drain_active = false;

    if !initial_payload.is_empty() {
        logical.write_all(&initial_payload).await.map_err(|err| {
            RelayError::new(format!("write VLESS mux initial payload: {err}"), &stats)
        })?;
        stats.client_to_proxy += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }
    drop(initial_payload);

    loop {
        tokio::select! {
            _ = stop_listener.cancelled() => break,
            inbound_read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match inbound_read {
                    Ok(0) => {
                        inbound_closed = true;
                        logical.shutdown().await.map_err(|err| {
                            RelayError::new(format!("shutdown VLESS mux logical upload: {err}"), &stats)
                        })?;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                        reset_resident_relay_idle_deadline(
                            close_drain_deadline.as_mut(),
                            RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT,
                        );
                        close_drain_active = true;
                    }
                    Ok(read) => {
                        logical
                            .write_all(&inbound_buf[..read])
                            .await
                            .map_err(|err| RelayError::new(format!("write VLESS mux logical payload: {err}"), &stats))?;
                        stats.client_to_proxy += read;
                        metrics.add_upload(read);
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        logical.shutdown().await.map_err(|err| {
                            RelayError::new(format!("shutdown VLESS mux logical upload: {err}"), &stats)
                        })?;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                        reset_resident_relay_idle_deadline(
                            close_drain_deadline.as_mut(),
                            RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT,
                        );
                        close_drain_active = true;
                    }
                    Err(err) => {
                        return Err(RelayError::new(format!("read inbound TCP for VLESS mux: {err}"), &stats));
                    }
                }
            }
            logical_read = logical.read(&mut logical_buf) => {
                match logical_read {
                    Ok(0) => break,
                    Ok(read) => {
                        inbound
                            .write_all(&logical_buf[..read])
                            .await
                            .map_err(|err| RelayError::new(format!("write VLESS mux payload to client: {err}"), &stats))?;
                        stats.proxy_to_client += read;
                        metrics.add_download(read);
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                        if close_drain_active {
                            reset_resident_relay_idle_deadline(
                                close_drain_deadline.as_mut(),
                                RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT,
                            );
                        }
                    }
                    Err(err) => {
                        return Err(RelayError::new(format!("read VLESS mux logical stream: {err}"), &stats));
                    }
                }
            }
            _ = &mut close_drain_deadline, if close_drain_active => break,
            _ = &mut idle_deadline => {
                return Err(RelayError::new("resident VLESS mux relay idle timeout", &stats));
            }
        }
    }
    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_vless_websocket_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let mut client =
        open_async_vless_tls_client_with_flow(&selection.proxy, selection.mark, selection.mptcp)
            .await?;
    let tls_underlay = async_tls_underlay_name(&client);
    let key = selection.proxy.vless_key()?;
    let options =
        HttpUpgradeOptions::new(&selection.proxy.stream_host, &selection.proxy.stream_path);
    websocket_handshake_over_resident_tls_async(&mut client, &options).await?;
    let initial_payload = sniff.take_payload();
    let initial_payload_len = initial_payload.len();
    let request = packet::first_write_bytes(
        &key,
        &selection.proxy.flow,
        "tcp",
        &selection.route.dial_target,
        false,
        &initial_payload,
    )
    .map_err(|err| format!("build VLESS WebSocket TCP request: {err}"))?;
    write_websocket_binary_frame_over_resident_tls_async(
        &mut client,
        &request,
        "write VLESS websocket request",
    )
    .await?;
    if initial_payload_len != 0 {
        metrics.add_upload(initial_payload_len);
    }
    drop((request, initial_payload));
    relay_tcp_over_vless_websocket_tls_async(
        inbound,
        &mut client,
        stop,
        initial_payload_len,
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
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let mut client =
        open_async_vless_tls_client_with_flow(&selection.proxy, selection.mark, selection.mptcp)
            .await?;
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
    drop(request);
    let initial_payload = sniff.take_payload();
    relay_tcp_over_vless_tls_async(
        inbound,
        &mut client,
        stop,
        &selection.proxy.flow,
        key,
        initial_payload,
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
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let tls_underlay = if selection.proxy.utls_fingerprint.is_some() {
        "boringssl"
    } else {
        "rustls"
    };
    let key = selection.proxy.vless_key()?;
    let options = meek_options_from_proxy(&selection, peer, original_dst);
    let initial_payload = sniff.take_payload();
    let initial_payload_len = initial_payload.len();
    let first_payload = packet::first_write_bytes(
        &key,
        "",
        "tcp",
        &selection.route.dial_target,
        false,
        &initial_payload,
    )
    .map_err(|err| format!("build VLESS Meek TCP request: {err}"))?;
    let mut stats = DirectTcpRelayStats::default();
    if initial_payload_len != 0 {
        stats.client_to_direct += initial_payload_len;
        metrics.add_upload(initial_payload_len);
    }
    drop(initial_payload);
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
