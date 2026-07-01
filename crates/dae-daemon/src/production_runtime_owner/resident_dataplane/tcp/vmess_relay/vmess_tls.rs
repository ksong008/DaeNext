use super::*;
pub(crate) async fn relay_tcp_over_vmess_tls_aead_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    client: &mut AsyncResidentTlsClient,
    stop: Arc<AtomicBool>,
    session: VMessAeadTcpClientSessionStart,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut upload_codec = session.upload;
    let mut response = aead_tcp_response_reader_from_async_stream(client, &session.request)
        .await
        .map_err(|err| format!("read VMess TLS AEAD response header: {err}"))?;
    let _response_header_len = response.response_header_len;
    let mut inbound_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];

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
                        let encrypted = upload_codec
                            .seal_chunk(&inbound_buf[..read])
                            .map_err(|err| format!("encode VMess TLS upload chunk: {err}"))?;
                        client
                            .write_plain_all(&encrypted, "write VMess TLS upload chunk")
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
                    Err(err) => return Err(format!("read inbound TCP for VMess TLS upload: {err}")),
                }
            }
            proxy_chunk = response.read_chunk_from_async_stream(client) => {
                match proxy_chunk {
                    Ok(plain) => {
                        if !plain.is_empty() {
                            inbound
                                .write_all(&plain)
                                .await
                                .map_err(|err| format!("write VMess TLS response to inbound: {err}"))?;
                            stats.direct_to_client += plain.len();
                            metrics.add_download(plain.len());
                        }
                        last_activity = Instant::now();
                    }
                    Err(err) => {
                        let message = err.to_string();
                        if is_graceful_vmess_response_message(&message) {
                            break;
                        }
                        return Err(format!("read VMess TLS response chunk: {message}"));
                    }
                }
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if inbound_closed {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident VMess TLS relay idle timeout".to_owned());
                }
            }
        }
    }
    Ok(stats)
}

pub(crate) async fn relay_tcp_over_vmess_websocket_tls_aead_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    client: &mut AsyncResidentTlsClient,
    stop: Arc<AtomicBool>,
    session: VMessAeadTcpClientSessionStart,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut upload_codec = session.upload;
    let mut ws_state = AsyncWebSocketPayloadState::default();
    let mut response = {
        let mut reader = AsyncWebSocketPayloadReader::new(client, &mut ws_state);
        aead_tcp_response_reader_from_async_stream(&mut reader, &session.request)
            .await
            .map_err(|err| format!("read VMess TLS WebSocket AEAD response header: {err}"))?
    };
    let _response_header_len = response.response_header_len;
    let mut inbound_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];

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
                        let encrypted = upload_codec
                            .seal_chunk(&inbound_buf[..read])
                            .map_err(|err| format!("encode VMess TLS WebSocket upload chunk: {err}"))?;
                        write_websocket_binary_frame_over_resident_tls_async(
                            client,
                            &encrypted,
                            "write VMess TLS websocket upload frame",
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
                    Err(err) => {
                        return Err(format!("read inbound TCP for VMess TLS WebSocket upload: {err}"));
                    }
                }
            }
            proxy_chunk = read_vmess_websocket_tls_response_chunk(client, &mut ws_state, &mut response) => {
                match proxy_chunk {
                    Ok(plain) => {
                        if !plain.is_empty() {
                            inbound
                                .write_all(&plain)
                                .await
                                .map_err(|err| format!("write VMess TLS WebSocket response to inbound: {err}"))?;
                            stats.direct_to_client += plain.len();
                            metrics.add_download(plain.len());
                        }
                        last_activity = Instant::now();
                    }
                    Err(err) => {
                        if is_graceful_vmess_response_message(&err) {
                            break;
                        }
                        return Err(err);
                    }
                }
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if inbound_closed {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident VMess TLS WebSocket relay idle timeout".to_owned());
                }
            }
        }
    }
    Ok(stats)
}

pub(crate) async fn read_vmess_websocket_tls_response_chunk(
    client: &mut AsyncResidentTlsClient,
    state: &mut AsyncWebSocketPayloadState,
    response: &mut dae_outbound::vmess::VMessAeadTcpResponseReader,
) -> Result<Vec<u8>, String> {
    let mut reader = AsyncWebSocketPayloadReader::new(client, state);
    response
        .read_chunk_from_async_stream(&mut reader)
        .await
        .map_err(|err| format!("read VMess TLS WebSocket response chunk: {err}"))
}
