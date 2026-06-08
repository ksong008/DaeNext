use super::*;
pub(crate) async fn relay_tcp_over_vless_websocket_tls_async(
    inbound: &mut TokioTcpStream,
    client: &mut AsyncVlessTlsClient,
    stop: Arc<AtomicBool>,
    initial_payload_len: usize,
    metrics: &ResidentDataplaneMetrics,
) -> Result<RelayStats, RelayError> {
    let mut stats = RelayStats::default();
    let mut stripper = VlessResponseStripper::default();
    let mut ws_decoder = WebSocketBinaryFrameDecoder::default();
    let mut inbound_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut proxy_buf = [0_u8; 16 * 1024];

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            inbound_read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match inbound_read {
                    Ok(0) => {
                        inbound_closed = true;
                        client.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        write_websocket_binary_frame_over_resident_tls_async(
                            client,
                            &inbound_buf[..read],
                            "write client payload websocket frame",
                        )
                        .await
                        .map_err(|err| RelayError::new(err, &stats))?;
                        stats.client_to_proxy += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        client.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Err(err) => {
                        return Err(RelayError::new(format!("read inbound TCP: {err}"), &stats));
                    }
                }
            }
            proxy_read = client.read_plain(&mut proxy_buf) => {
                match proxy_read {
                    Ok(0) => break,
                    Ok(read) => {
                        let frames = ws_decoder
                            .push(&proxy_buf[..read])
                            .map_err(|err| RelayError::new(err, &stats))?;
                        for frame in frames {
                            let payload = stripper
                                .consume(&frame)
                                .map_err(|err| RelayError::new(err, &stats))?;
                            stats.response_header_stripped = stripper.done;
                            if !payload.is_empty() {
                                inbound
                                    .write_all(&payload)
                                    .await
                                    .map_err(|err| RelayError::new(format!("write VLESS websocket payload to client: {err}"), &stats))?;
                                stats.proxy_to_client += payload.len();
                                metrics.add_download(payload.len());
                            }
                        }
                        last_activity = Instant::now();
                    }
                    Err(err) => {
                        return Err(RelayError::new(format!("read websocket TLS plaintext: {err}"), &stats));
                    }
                }
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if inbound_closed {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err(RelayError::new("resident websocket relay idle timeout", &stats));
                }
            }
        }
    }
    stats.client_to_proxy += initial_payload_len;
    Ok(stats)
}

pub(crate) async fn relay_tcp_over_trojan_websocket_tls_async(
    inbound: &mut TokioTcpStream,
    client: &mut AsyncResidentTlsClient,
    stop: Arc<AtomicBool>,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut stats = DirectTcpRelayStats::default();
    let mut ws_decoder = WebSocketBinaryFrameDecoder::default();
    let mut inbound_closed = false;
    let mut proxy_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut proxy_buf = [0_u8; 16 * 1024];

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            inbound_read = inbound.read(&mut inbound_buf), if !inbound_closed && !proxy_closed => {
                match inbound_read {
                    Ok(0) => {
                        inbound_closed = true;
                        client.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        write_websocket_binary_frame_over_resident_tls_async(
                            client,
                            &inbound_buf[..read],
                            "write client payload websocket frame",
                        )
                        .await?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        client.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read inbound TCP for Trojan websocket relay: {err}")),
                }
            }
            proxy_read = client.read_plain(&mut proxy_buf), if !proxy_closed => {
                match proxy_read {
                    Ok(0) => {
                        proxy_closed = true;
                        let _ = inbound.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        let frames = ws_decoder
                            .push(&proxy_buf[..read])
                            .map_err(|err| format!("decode Trojan websocket frame: {err}"))?;
                        for payload in frames {
                            if !payload.is_empty() {
                                if let Err(err) = inbound.write_all(&payload).await {
                                    if is_graceful_stream_close_error(&err) {
                                        break;
                                    }
                                    return Err(format!("write Trojan websocket payload to client: {err}"));
                                }
                                stats.direct_to_client += payload.len();
                                metrics.add_download(payload.len());
                            }
                        }
                        if ws_decoder.is_closed() {
                            proxy_closed = true;
                            let _ = inbound.shutdown().await;
                        }
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read Trojan websocket TLS plaintext: {err}")),
                }
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if proxy_closed || inbound_closed {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident Trojan websocket relay idle timeout".to_owned());
                }
            }
        }

        if proxy_closed || (inbound_closed && proxy_closed) {
            break;
        }
    }
    Ok(stats)
}
