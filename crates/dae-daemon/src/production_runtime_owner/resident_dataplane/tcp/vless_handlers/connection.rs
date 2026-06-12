use super::*;
pub(crate) async fn handle_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    if matches!(
        &selection.proxy.handler,
        ResidentProxyProtocolPlan::VlessMuxTcpTls { .. }
    ) {
        return handle_vless_mux_tcp_connection_async(
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
pub(crate) async fn handle_vless_mux_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let mut client =
        open_async_vless_tls_client_with_flow(&selection.proxy, selection.mark, selection.mptcp)
            .await?;
    let tls_underlay = async_tls_underlay_name(&client);
    let key = selection.proxy.vless_key()?;
    let header = packet::request_header(&key, "", "tcp", "0.0.0.0:0", true, &[])
        .map_err(|err| format!("build VLESS mux request header: {err}"))?;
    let mux_target = VMessMetadata::parse("tcp", &selection.route.dial_target)
        .map_err(|err| format!("build VLESS mux target metadata: {err}"))?;
    let mux_id = resident_mux_stream_id(original_dst);
    let mux_options = MuxFrameOptions::new(mux_id, mux_target.hostname(), mux_target.port(), "tcp");
    let mux_new =
        mux_new_frame(&mux_options).map_err(|err| format!("build VLESS mux new frame: {err}"))?;
    client
        .write_plain_all(&header, "write VLESS mux request header")
        .await?;
    client
        .write_plain_all(&mux_new, "write VLESS mux new frame")
        .await?;
    relay_tcp_over_vless_mux_tls_async(inbound, &mut client, stop, mux_id, &sniff.payload, metrics)
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
            Ok::<Value, String>(event)
        })
}

fn resident_mux_stream_id(original_dst: SocketAddr) -> [u8; 2] {
    original_dst.port().to_be_bytes()
}

pub(crate) async fn relay_tcp_over_vless_mux_tls_async(
    inbound: &mut TokioTcpStream,
    client: &mut AsyncVlessTlsClient,
    stop: Arc<AtomicBool>,
    mux_id: [u8; 2],
    initial_payload: &[u8],
    metrics: &ResidentDataplaneMetrics,
) -> Result<RelayStats, RelayError> {
    let mut stats = RelayStats::default();
    let mut response_stripper = VlessResponseStripper::default();
    let mut mux_buffer = AsyncMuxFrameBuffer::default();
    let mut inbound_closed = false;
    let mut mux_ended = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut proxy_buf = [0_u8; 16 * 1024];

    if !initial_payload.is_empty() {
        let frame = mux_data_frame(mux_id, initial_payload).map_err(|err| {
            RelayError::new(format!("build VLESS mux initial data frame: {err}"), &stats)
        })?;
        client
            .write_plain_all(&frame, "write VLESS mux initial data frame")
            .await
            .map_err(|err| RelayError::new(err, &stats))?;
        stats.client_to_proxy += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            inbound_read = inbound.read(&mut inbound_buf), if !inbound_closed && !mux_ended => {
                match inbound_read {
                    Ok(0) => {
                        inbound_closed = true;
                        client
                            .write_plain_all(&mux_end_frame(mux_id), "write VLESS mux end frame")
                            .await
                            .map_err(|err| RelayError::new(err, &stats))?;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        let frame = mux_data_frame(mux_id, &inbound_buf[..read])
                            .map_err(|err| RelayError::new(format!("build VLESS mux upload data frame: {err}"), &stats))?;
                        client
                            .write_plain_all(&frame, "write VLESS mux upload data frame")
                            .await
                            .map_err(|err| RelayError::new(err, &stats))?;
                        stats.client_to_proxy += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        client
                            .write_plain_all(&mux_end_frame(mux_id), "write VLESS mux end frame")
                            .await
                            .map_err(|err| RelayError::new(err, &stats))?;
                        last_activity = Instant::now();
                    }
                    Err(err) => {
                        return Err(RelayError::new(format!("read inbound TCP for VLESS mux: {err}"), &stats));
                    }
                }
            }
            proxy_read = client.read_plain(&mut proxy_buf), if !mux_ended => {
                match proxy_read {
                    Ok(0) => break,
                    Ok(read) => {
                        let proxy_payload = if response_stripper.done {
                            proxy_buf[..read].to_vec()
                        } else {
                            let payload = response_stripper
                                .consume(&proxy_buf[..read])
                                .map_err(|err| RelayError::new(err, &stats))?;
                            stats.response_header_stripped = response_stripper.done;
                            payload
                        };
                        if proxy_payload.is_empty() {
                            last_activity = Instant::now();
                            continue;
                        }
                        let event = mux_buffer
                            .push(&proxy_payload, mux_id)
                            .map_err(|err| RelayError::new(err, &stats))?;
                        for payload in event.payloads {
                            if payload.is_empty() {
                                continue;
                            }
                            inbound
                                .write_all(&payload)
                                .await
                                .map_err(|err| RelayError::new(format!("write VLESS mux payload to client: {err}"), &stats))?;
                            stats.proxy_to_client += payload.len();
                            metrics.add_download(payload.len());
                        }
                        if event.ended {
                            mux_ended = true;
                            let _ = inbound.shutdown().await;
                        }
                        last_activity = Instant::now();
                    }
                    Err(err) => {
                        return Err(RelayError::new(format!("read VLESS mux TLS plaintext: {err}"), &stats));
                    }
                }
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if mux_ended || inbound_closed {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err(RelayError::new("resident VLESS mux relay idle timeout", &stats));
                }
            }
        }
    }
    Ok(stats)
}

#[derive(Default)]
struct AsyncMuxFrameBuffer {
    pending: VecDeque<u8>,
}

#[derive(Default)]
struct AsyncMuxFrameEvent {
    payloads: Vec<Vec<u8>>,
    ended: bool,
}

impl AsyncMuxFrameBuffer {
    fn push(&mut self, bytes: &[u8], expected_id: [u8; 2]) -> Result<AsyncMuxFrameEvent, String> {
        self.pending.extend(bytes.iter().copied());
        let mut event = AsyncMuxFrameEvent::default();
        loop {
            let Some((frame_end, status, option, payload)) = ({
                let pending = self.pending.make_contiguous();
                if pending.len() < 2 {
                    break;
                };
                let metadata_len = u16::from_be_bytes([pending[0], pending[1]]) as usize;
                if !(4..=512).contains(&metadata_len) {
                    return Err("invalid VLESS mux metadata length".to_owned());
                }
                let metadata_end = 2 + metadata_len;
                if pending.len() < metadata_end {
                    break;
                }
                let metadata = &pending[2..metadata_end];
                let frame_id = [metadata[0], metadata[1]];
                if frame_id != expected_id {
                    return Err("VLESS mux frame id mismatch".to_owned());
                }
                let status = metadata[2];
                let option = metadata[3];
                if status == SESSION_STATUS_KEEPALIVE {
                    Some((metadata_end, status, option, Vec::new()))
                } else {
                    let mut frame_end = metadata_end;
                    let payload = if option == OPTION_DATA {
                        if pending.len() < metadata_end + 2 {
                            break;
                        }
                        let payload_len =
                            u16::from_be_bytes([pending[metadata_end], pending[metadata_end + 1]])
                                as usize;
                        frame_end += 2 + payload_len;
                        if pending.len() < frame_end {
                            break;
                        }
                        pending[metadata_end + 2..frame_end].to_vec()
                    } else {
                        Vec::new()
                    };
                    Some((frame_end, status, option, payload))
                }
            }) else {
                break;
            };
            self.pending.drain(..frame_end);
            if status == SESSION_STATUS_END {
                event.ended = true;
            } else if status == SESSION_STATUS_KEEP && option == OPTION_DATA {
                event.payloads.push(payload);
            }
        }
        Ok(event)
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_vless_websocket_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
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
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
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
    original_dst: SocketAddr,
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
