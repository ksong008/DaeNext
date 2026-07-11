use super::*;

pub(crate) async fn relay_tcp_over_vmess_aead_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    proxy: &mut TokioTcpStream,
    stop: SharedResidentStopSignal,
    session: VMessAeadTcpClientSessionStart,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut upload_codec = session.upload;
    let mut response = aead_tcp_response_reader_from_async_stream(proxy, &session.request)
        .await
        .map_err(|err| format!("read VMess AEAD response header: {err}"))?;
    let _response_header_len = response.response_header_len;
    let mut inbound_closed = false;
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut stop_listener = stop.listener();
    let idle_deadline = resident_relay_idle_deadline(RESIDENT_TCP_IDLE_TIMEOUT);
    let close_drain_deadline =
        resident_relay_idle_deadline(RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT);
    tokio::pin!(idle_deadline);
    tokio::pin!(close_drain_deadline);
    let mut close_drain_active = false;

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
                        let encrypted = upload_codec
                            .seal_chunk(&inbound_buf[..read])
                            .map_err(|err| format!("encode VMess upload chunk: {err}"))?;
                        proxy
                            .write_all(&encrypted)
                            .await
                            .map_err(|err| format!("write VMess upload chunk: {err}"))?;
                        stats.client_to_direct += read;
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
                    Err(err) => return Err(format!("read inbound TCP for VMess upload: {err}")),
                }
            }
            proxy_chunk = response.read_chunk_from_async_stream(proxy) => {
                match proxy_chunk {
                    Ok(plain) => {
                        if !plain.is_empty() {
                            inbound
                                .write_all(&plain)
                                .await
                                .map_err(|err| format!("write VMess response to inbound: {err}"))?;
                            stats.direct_to_client += plain.len();
                            metrics.add_download(plain.len());
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
                        let message = err.to_string();
                        if is_graceful_vmess_response_message(&message) {
                            break;
                        }
                        return Err(format!("read VMess response chunk: {message}"));
                    }
                }
            }
            _ = &mut close_drain_deadline, if close_drain_active => break,
            _ = &mut idle_deadline => {
                return Err("resident VMess relay idle timeout".to_owned());
            }
        }
    }
    Ok(stats)
}

pub(crate) async fn relay_tcp_over_vmess_websocket_aead_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    proxy: &mut TokioTcpStream,
    stop: SharedResidentStopSignal,
    session: VMessAeadTcpClientSessionStart,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut upload_codec = session.upload;
    let mut ws_state = AsyncWebSocketPayloadState::default();
    let mut response = {
        let mut reader = AsyncWebSocketPayloadReader::new(proxy, &mut ws_state);
        aead_tcp_response_reader_from_async_stream(&mut reader, &session.request)
            .await
            .map_err(|err| format!("read VMess WebSocket AEAD response header: {err}"))?
    };
    let _response_header_len = response.response_header_len;
    let mut inbound_closed = false;
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut stop_listener = stop.listener();
    let idle_deadline = resident_relay_idle_deadline(RESIDENT_TCP_IDLE_TIMEOUT);
    let close_drain_deadline =
        resident_relay_idle_deadline(RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT);
    tokio::pin!(idle_deadline);
    tokio::pin!(close_drain_deadline);
    let mut close_drain_active = false;

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
                        let encrypted = upload_codec
                            .seal_chunk(&inbound_buf[..read])
                            .map_err(|err| format!("encode VMess WebSocket upload chunk: {err}"))?;
                        write_websocket_binary_frame_to_async_stream(
                            proxy,
                            &encrypted,
                            "write VMess websocket upload frame",
                        )
                        .await?;
                        stats.client_to_direct += read;
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
                        return Err(format!("read inbound TCP for VMess WebSocket upload: {err}"));
                    }
                }
            }
            proxy_chunk = read_vmess_websocket_plain_response_chunk(proxy, &mut ws_state, &mut response) => {
                match proxy_chunk {
                    Ok(plain) => {
                        if !plain.is_empty() {
                            inbound
                                .write_all(&plain)
                                .await
                                .map_err(|err| format!("write VMess WebSocket response to inbound: {err}"))?;
                            stats.direct_to_client += plain.len();
                            metrics.add_download(plain.len());
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
                        if is_graceful_vmess_response_message(&err) {
                            break;
                        }
                        return Err(err);
                    }
                }
            }
            _ = &mut close_drain_deadline, if close_drain_active => break,
            _ = &mut idle_deadline => {
                return Err("resident VMess WebSocket relay idle timeout".to_owned());
            }
        }
    }
    Ok(stats)
}

pub(crate) async fn read_vmess_websocket_plain_response_chunk(
    proxy: &mut TokioTcpStream,
    state: &mut AsyncWebSocketPayloadState,
    response: &mut dae_outbound::vmess::VMessAeadTcpResponseReader,
) -> Result<Vec<u8>, String> {
    let mut reader = AsyncWebSocketPayloadReader::new(proxy, state);
    response
        .read_chunk_from_async_stream(&mut reader)
        .await
        .map_err(|err| format!("read VMess WebSocket response chunk: {err}"))
}
