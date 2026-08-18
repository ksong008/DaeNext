use super::*;

#[derive(Clone, Copy)]
pub(super) struct VmessTransportRelayPolicy {
    pub(super) label: &'static str,
    pub(super) idle_error: &'static str,
    pub(super) flush_upload: bool,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn relay_tcp_over_vmess_stream_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    proxy: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    stop: SharedResidentStopSignal,
    session: VMessAeadTcpClientSessionStart,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
    policy: VmessTransportRelayPolicy,
    leftover: Vec<u8>,
) -> Result<DirectTcpRelayStats, String> {
    let VmessTransportRelayPolicy {
        label,
        idle_error,
        flush_upload,
    } = policy;
    let (progress, activity) = resident_duplex_progress();
    if stats.client_to_direct != 0 {
        progress.record_upload(stats.client_to_direct);
    }
    if stats.direct_to_client != 0 {
        progress.record_download(stats.direct_to_client);
    }
    let mut upload_codec = session.upload;
    let mut response = VmessAeadResponseBuffer::new(session.request);
    let (inbound_read, inbound_write) = tokio::io::split(&mut *inbound);
    let (proxy_read, proxy_write) = tokio::io::split(&mut *proxy);
    let upload_progress = progress.clone();
    let upload = async move {
        let mut inbound_read = inbound_read;
        let mut proxy_write = proxy_write;
        let mut buffer = Box::new([0_u8; VMESS_AEAD_TCP_UPLOAD_BUFFER_SIZE]);
        loop {
            let read = match inbound_read
                .read(upload_codec.chunk_payload_buffer(buffer.as_mut()))
                .await
            {
                Ok(0) => {
                    let _ = proxy_write.shutdown().await;
                    return Ok(());
                }
                Ok(read) => read,
                Err(err) if is_graceful_stream_close_error(&err) => {
                    let _ = proxy_write.shutdown().await;
                    return Ok(());
                }
                Err(err) => return Err(format!("read inbound TCP for {label} upload: {err}")),
            };
            let wire_len = upload_codec
                .seal_chunk_in_place(buffer.as_mut(), read)
                .map_err(|err| format!("encode {label} upload chunk: {err}"))?;
            proxy_write
                .write_all(&buffer[..wire_len])
                .await
                .map_err(|err| format!("write {label} upload chunk: {err}"))?;
            if flush_upload {
                proxy_write
                    .flush()
                    .await
                    .map_err(|err| format!("flush {label} upload chunk: {err}"))?;
            }
            upload_progress.record_upload(read);
            metrics.add_upload(read);
        }
    };
    let download_progress = progress.clone();
    let download = async move {
        let mut inbound_write = inbound_write;
        let mut proxy_read = proxy_read;
        let mut buffer = [0_u8; 16 * 1024];
        // A-14: 握手同批 leftover 是服务端首段数据，先转发给客户端。
        if !leftover.is_empty() {
            inbound_write
                .write_all(&leftover)
                .await
                .map_err(|err| format!("write {label} leftover to client: {err}"))?;
        }
        loop {
            let read = match proxy_read.read(&mut buffer).await {
                Ok(0) if response.response_header_received() => {
                    let _ = inbound_write.shutdown().await;
                    return Ok(());
                }
                Ok(0) => return Err(format!("{label} closed before the response header")),
                Ok(read) => read,
                Err(err) => {
                    let message = err.to_string();
                    if response.response_header_received()
                        && is_graceful_vmess_response_message(&message)
                    {
                        let _ = inbound_write.shutdown().await;
                        return Ok(());
                    }
                    return Err(format!("read {label} response: {message}"));
                }
            };
            response.extend_from_slice(&buffer[..read])?;
            while let Some(plain) = response.next_chunk()? {
                if plain.is_empty() {
                    continue;
                }
                inbound_write
                    .write_all(plain)
                    .await
                    .map_err(|err| format!("write {label} response to inbound: {err}"))?;
                download_progress.record_download(plain.len());
                metrics.add_download(plain.len());
            }
        }
    };
    run_resident_duplex_relay(
        Box::pin(upload),
        Box::pin(download),
        stop,
        &progress,
        activity,
        idle_error,
        Some(RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn relay_tcp_over_vmess_websocket_stream_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    proxy: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    stop: SharedResidentStopSignal,
    session: VMessAeadTcpClientSessionStart,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
    policy: VmessTransportRelayPolicy,
    leftover: Vec<u8>,
) -> Result<DirectTcpRelayStats, String> {
    let VmessTransportRelayPolicy {
        label, idle_error, ..
    } = policy;
    let (progress, activity) = resident_duplex_progress();
    if stats.client_to_direct != 0 {
        progress.record_upload(stats.client_to_direct);
    }
    if stats.direct_to_client != 0 {
        progress.record_download(stats.direct_to_client);
    }
    let mut upload_codec = session.upload;
    let mut response = VmessAeadResponseBuffer::new(session.request);
    let (control_tx, mut control_rx) = websocket_control_channel();
    let (inbound_read, inbound_write) = tokio::io::split(&mut *inbound);
    let (proxy_read, proxy_write) = tokio::io::split(&mut *proxy);
    let upload_progress = progress.clone();
    let upload = async move {
        let mut inbound_read = inbound_read;
        let mut proxy_write = proxy_write;
        let mut buffer = Box::new([0_u8; VMESS_AEAD_TCP_UPLOAD_BUFFER_SIZE]);
        loop {
            tokio::select! {
                biased;
                control = control_rx.recv() => {
                    let Some(control) = control else {
                        return Ok(());
                    };
                    write_websocket_control_response(&mut proxy_write, control, label).await?;
                }
                read = inbound_read.read(upload_codec.chunk_payload_buffer(buffer.as_mut())) => {
                    let read = match read {
                        Ok(0) => {
                            return Ok(());
                        }
                        Ok(read) => read,
                        Err(err) if is_graceful_stream_close_error(&err) => {
                            return Ok(());
                        }
                        Err(err) => return Err(format!("read inbound TCP for {label} upload: {err}")),
                    };
                    let wire_len = upload_codec
                        .seal_chunk_in_place(buffer.as_mut(), read)
                        .map_err(|err| format!("encode {label} upload chunk: {err}"))?;
                    write_websocket_binary_frame_in_place_to_async_stream(
                        &mut proxy_write,
                        &mut buffer[..wire_len],
                        "write VMess WebSocket upload frame",
                    )
                    .await?;
                    upload_progress.record_upload(read);
                    metrics.add_upload(read);
                }
            }
        }
    };
    let download_progress = progress.clone();
    let download = async move {
        let mut inbound_write = inbound_write;
        let mut proxy_read = proxy_read;
        let mut decoder = WebSocketBinaryFrameDecoder::default();
        // A-14: 握手同批 leftover 是服务端首帧，先喂解码器。
        if !leftover.is_empty() {
            decoder
                .extend(&leftover)
                .map_err(|err| format!("decode {label} leftover frame: {err}"))?;
        }
        let mut buffer = [0_u8; RESIDENT_WEBSOCKET_RELAY_BUFFER_SIZE];
        loop {
            let read = match proxy_read.read(&mut buffer).await {
                Ok(0) if response.response_header_received() => {
                    let _ = inbound_write.shutdown().await;
                    return Ok(());
                }
                Ok(0) => return Err(format!("{label} closed before the response header")),
                Ok(read) => read,
                Err(err) => {
                    let message = err.to_string();
                    if response.response_header_received()
                        && is_graceful_vmess_response_message(&message)
                    {
                        let _ = inbound_write.shutdown().await;
                        return Ok(());
                    }
                    return Err(format!("read {label} response: {message}"));
                }
            };
            decoder
                .extend(&buffer[..read])
                .map_err(|err| format!("decode {label} response frame: {err}"))?;
            while let Some(frame) = decoder
                .next_message()
                .map_err(|err| format!("decode {label} response frame: {err}"))?
            {
                response.extend_from_slice(frame)?;
                while let Some(plain) = response.next_chunk()? {
                    if plain.is_empty() {
                        continue;
                    }
                    inbound_write
                        .write_all(plain)
                        .await
                        .map_err(|err| format!("write {label} response to inbound: {err}"))?;
                    download_progress.record_download(plain.len());
                    metrics.add_download(plain.len());
                }
            }
            queue_websocket_control_responses(&mut decoder, &control_tx, label).await?;
            if decoder.is_closed() {
                if !response.response_header_received() {
                    return Err(format!("{label} closed before the response header"));
                }
                let _ = inbound_write.shutdown().await;
                return Ok(());
            }
        }
    };
    run_resident_duplex_relay(
        Box::pin(upload),
        Box::pin(download),
        stop,
        &progress,
        activity,
        idle_error,
        Some(RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_UUID: &str = "11111111-1111-4111-8111-111111111111";
    const TEST_TARGET: &str = "example.com:443";
    const DELAYED_REQUEST: &[u8] = b"delayed application request";
    const DELAYED_RESPONSE: &[u8] = b"delayed application response";

    #[tokio::test]
    async fn raw_relay_uploads_delayed_first_payload_before_response_header() {
        let session = aead_tcp_client_session_start(TEST_UUID, TEST_TARGET, &[]).unwrap();
        let request = session.request.clone();
        let request_header_len = session.first_write.len();
        let (mut inbound, mut application) = tokio::io::duplex(64 * 1024);
        let (mut proxy, mut server) = tokio::io::duplex(64 * 1024);
        proxy.write_all(&session.first_write).await.unwrap();
        let stop = ResidentStopSignal::shared();
        let metrics = ResidentDataplaneMetrics::default();

        let relay = relay_tcp_over_vmess_aead_async(
            &mut inbound,
            &mut proxy,
            stop,
            session,
            DirectTcpRelayStats::default(),
            &metrics,
            Vec::new(),
        );
        let server = async move {
            let mut header = vec![0_u8; request_header_len];
            server.read_exact(&mut header).await.unwrap();
            let mut delayed_upload = [0_u8; 1];
            time::timeout(
                Duration::from_secs(1),
                server.read_exact(&mut delayed_upload),
            )
            .await
            .expect("VMess relay must upload application data before a response header")
            .unwrap();
            let response =
                dae_outbound::vmess::aead_tcp_response_packet(&request, DELAYED_RESPONSE).unwrap();
            server.write_all(&response).await.unwrap();
            server.shutdown().await.unwrap();
        };
        let application = async move {
            time::sleep(Duration::from_millis(20)).await;
            application.write_all(DELAYED_REQUEST).await.unwrap();
            application.shutdown().await.unwrap();
            let mut response = vec![0_u8; DELAYED_RESPONSE.len()];
            application.read_exact(&mut response).await.unwrap();
            assert_eq!(response, DELAYED_RESPONSE);
        };

        let (relay, (), ()) = tokio::join!(relay, server, application);
        let stats = relay.unwrap();
        assert_eq!(stats.client_to_direct, DELAYED_REQUEST.len());
        assert_eq!(stats.direct_to_client, DELAYED_RESPONSE.len());
    }

    #[tokio::test]
    async fn websocket_relay_uploads_delayed_first_payload_before_response_header() {
        let session = aead_tcp_client_session_start(TEST_UUID, TEST_TARGET, &[]).unwrap();
        let request = session.request.clone();
        let first_frame =
            dae_outbound::shared_transport::websocket_client_binary_frame_with_random_mask(
                &session.first_write,
            )
            .unwrap();
        let first_frame_len = first_frame.len();
        let (mut inbound, mut application) = tokio::io::duplex(64 * 1024);
        let (mut proxy, mut server) = tokio::io::duplex(64 * 1024);
        proxy.write_all(&first_frame).await.unwrap();
        let stop = ResidentStopSignal::shared();
        let metrics = ResidentDataplaneMetrics::default();

        let relay = relay_tcp_over_vmess_websocket_aead_async(
            &mut inbound,
            &mut proxy,
            stop,
            session,
            DirectTcpRelayStats::default(),
            &metrics,
            Vec::new(),
        );
        let server = async move {
            let mut header_frame = vec![0_u8; first_frame_len];
            server.read_exact(&mut header_frame).await.unwrap();
            let mut delayed_upload_frame = [0_u8; 1];
            time::timeout(
                Duration::from_secs(1),
                server.read_exact(&mut delayed_upload_frame),
            )
            .await
            .expect("VMess WebSocket relay must upload before a response header")
            .unwrap();
            let response =
                dae_outbound::vmess::aead_tcp_response_packet(&request, DELAYED_RESPONSE).unwrap();
            let response_frame =
                dae_outbound::shared_transport::websocket_server_binary_frame(&response).unwrap();
            server.write_all(&response_frame).await.unwrap();
            server.shutdown().await.unwrap();
        };
        let application = async move {
            time::sleep(Duration::from_millis(20)).await;
            application.write_all(DELAYED_REQUEST).await.unwrap();
            application.shutdown().await.unwrap();
            let mut response = vec![0_u8; DELAYED_RESPONSE.len()];
            application.read_exact(&mut response).await.unwrap();
            assert_eq!(response, DELAYED_RESPONSE);
        };

        let (relay, (), ()) = tokio::join!(relay, server, application);
        let stats = relay.unwrap();
        assert_eq!(stats.client_to_direct, DELAYED_REQUEST.len());
        assert_eq!(stats.direct_to_client, DELAYED_RESPONSE.len());
    }

    #[tokio::test]
    async fn websocket_relay_answers_ping_while_waiting_for_response_payload() {
        let session = aead_tcp_client_session_start(TEST_UUID, TEST_TARGET, &[]).unwrap();
        let request = session.request.clone();
        let first_frame =
            dae_outbound::shared_transport::websocket_client_binary_frame_with_random_mask(
                &session.first_write,
            )
            .unwrap();
        let first_frame_len = first_frame.len();
        let (mut inbound, mut application) = tokio::io::duplex(64 * 1024);
        let (mut proxy, mut server) = tokio::io::duplex(64 * 1024);
        proxy.write_all(&first_frame).await.unwrap();
        let stop = ResidentStopSignal::shared();
        let metrics = ResidentDataplaneMetrics::default();

        let relay = relay_tcp_over_vmess_websocket_aead_async(
            &mut inbound,
            &mut proxy,
            stop,
            session,
            DirectTcpRelayStats::default(),
            &metrics,
            Vec::new(),
        );
        let server = async move {
            let mut header_frame = vec![0_u8; first_frame_len];
            server.read_exact(&mut header_frame).await.unwrap();

            let ping_payload = b"keepalive";
            let mut ping = vec![0x89, ping_payload.len() as u8];
            ping.extend_from_slice(ping_payload);
            server.write_all(&ping).await.unwrap();

            let mut pong = vec![0_u8; 2 + 4 + ping_payload.len()];
            time::timeout(Duration::from_secs(1), server.read_exact(&mut pong))
                .await
                .expect("VMess WebSocket relay must answer a server ping")
                .unwrap();
            assert_eq!(pong[0] & 0x0f, 0x0a);
            assert_ne!(pong[1] & 0x80, 0);

            let response =
                dae_outbound::vmess::aead_tcp_response_packet(&request, DELAYED_RESPONSE).unwrap();
            let response_frame =
                dae_outbound::shared_transport::websocket_server_binary_frame(&response).unwrap();
            server.write_all(&response_frame).await.unwrap();
            server.shutdown().await.unwrap();
        };
        let application = async move {
            let mut response = vec![0_u8; DELAYED_RESPONSE.len()];
            application.read_exact(&mut response).await.unwrap();
            assert_eq!(response, DELAYED_RESPONSE);
        };

        let (relay, (), ()) = tokio::join!(relay, server, application);
        let stats = relay.unwrap();
        assert_eq!(stats.client_to_direct, 0);
        assert_eq!(stats.direct_to_client, DELAYED_RESPONSE.len());
    }

    #[tokio::test]
    async fn raw_relay_stop_cancels_wait_before_response_header() {
        let session = aead_tcp_client_session_start(TEST_UUID, TEST_TARGET, &[]).unwrap();
        let (mut inbound, _application) = tokio::io::duplex(64 * 1024);
        let (mut proxy, _server) = tokio::io::duplex(64 * 1024);
        proxy.write_all(&session.first_write).await.unwrap();
        let stop = ResidentStopSignal::shared();
        let relay_stop = Arc::clone(&stop);
        let metrics = ResidentDataplaneMetrics::default();

        let relay = relay_tcp_over_vmess_aead_async(
            &mut inbound,
            &mut proxy,
            stop,
            session,
            DirectTcpRelayStats::default(),
            &metrics,
            Vec::new(),
        );
        let cancel = async move {
            time::sleep(Duration::from_millis(20)).await;
            relay_stop.store(true, Ordering::Relaxed);
        };

        let (relay, ()) = tokio::join!(relay, cancel);
        let stats = relay.unwrap();
        assert_eq!(stats.client_to_direct, 0);
        assert_eq!(stats.direct_to_client, 0);
    }
}
