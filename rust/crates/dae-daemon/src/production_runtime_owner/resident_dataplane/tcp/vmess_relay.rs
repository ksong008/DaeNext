fn relay_tcp_over_vmess_aead(
    inbound: &mut TcpStream,
    proxy: &mut TcpStream,
    stop: &AtomicBool,
    session: VMessAeadTcpClientSessionStart,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut upload_proxy = proxy
        .try_clone()
        .map_err(|err| format!("clone VMess proxy stream for upload: {err}"))?;
    let mut upload_inbound = inbound
        .try_clone()
        .map_err(|err| format!("clone inbound stream for VMess upload: {err}"))?;
    upload_inbound
        .set_read_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set VMess upload read timeout: {err}"))?;
    let relay_done = Arc::new(AtomicBool::new(false));
    let upload_done = Arc::clone(&relay_done);
    let mut upload_codec = session.upload;
    let upload = thread::spawn(move || {
        let mut stats = 0_usize;
        let mut buf = [0_u8; 16 * 1024];
        loop {
            if upload_done.load(Ordering::Relaxed) {
                break;
            }
            let read = match upload_inbound.read(&mut buf) {
                Ok(0) => break,
                Ok(read) => read,
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(err) if is_graceful_stream_close_error(&err) => break,
                Err(err) => return Err(format!("read inbound TCP for VMess upload: {err}")),
            };
            let encrypted = upload_codec
                .seal_chunk(&buf[..read])
                .map_err(|err| format!("encode VMess upload chunk: {err}"))?;
            if let Err(err) = upload_proxy.write_all(&encrypted) {
                if is_graceful_stream_close_error(&err) {
                    break;
                }
                return Err(format!("write VMess upload chunk: {err}"));
            }
            stats += read;
        }
        let _ = upload_proxy.shutdown(Shutdown::Write);
        Ok::<usize, String>(stats)
    });

    let mut response = match aead_tcp_response_reader_from_stream(proxy, &session.request) {
        Ok(response) => response,
        Err(err) => {
            relay_done.store(true, Ordering::Relaxed);
            let _ = inbound.shutdown(Shutdown::Read);
            let _ = proxy.shutdown(Shutdown::Write);
            let _ = upload.join();
            return Err(format!("read VMess AEAD response header: {err}"));
        }
    };
    let _response_header_len = response.response_header_len;

    let mut download_error = None;
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match response.read_chunk_from_stream(proxy) {
            Ok(plain) => {
                if plain.is_empty() {
                    continue;
                }
                inbound
                    .write_all(&plain)
                    .map_err(|err| format!("write VMess response to inbound: {err}"))?;
                stats.direct_to_client += plain.len();
                metrics.add_download(plain.len());
            }
            Err(err) => {
                let message = err.to_string();
                if message.contains("early eof")
                    || message.contains("failed to fill whole buffer")
                    || message.contains("Connection reset")
                    || message.contains("connection reset")
                    || message.contains("timed out")
                {
                    break;
                }
                download_error = Some(format!("read VMess response chunk: {message}"));
                break;
            }
        }
    }
    relay_done.store(true, Ordering::Relaxed);
    let _ = inbound.shutdown(Shutdown::Read);
    let _ = proxy.shutdown(Shutdown::Write);
    let upload_bytes = upload
        .join()
        .map_err(|_| "join VMess upload relay thread failed".to_owned())??;
    if let Some(err) = download_error {
        return Err(err);
    }
    if upload_bytes > 0 {
        stats.client_to_direct += upload_bytes;
        metrics.add_upload(upload_bytes);
    }
    Ok(stats)
}

fn relay_tcp_over_vmess_websocket_aead(
    inbound: &mut TcpStream,
    proxy: &mut TcpStream,
    stop: &AtomicBool,
    session: VMessAeadTcpClientSessionStart,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut upload_proxy = proxy
        .try_clone()
        .map_err(|err| format!("clone VMess WebSocket proxy stream for upload: {err}"))?;
    let mut upload_inbound = inbound
        .try_clone()
        .map_err(|err| format!("clone inbound stream for VMess WebSocket upload: {err}"))?;
    upload_inbound
        .set_read_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set VMess WebSocket upload read timeout: {err}"))?;
    let relay_done = Arc::new(AtomicBool::new(false));
    let upload_done = Arc::clone(&relay_done);
    let mut upload_codec = session.upload;
    let upload = thread::spawn(move || {
        let mut stats = 0_usize;
        let mut buf = [0_u8; 16 * 1024];
        loop {
            if upload_done.load(Ordering::Relaxed) {
                break;
            }
            let read = match upload_inbound.read(&mut buf) {
                Ok(0) => break,
                Ok(read) => read,
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(err) if is_graceful_stream_close_error(&err) => break,
                Err(err) => {
                    return Err(format!(
                        "read inbound TCP for VMess WebSocket upload: {err}"
                    ));
                }
            };
            let encrypted = upload_codec
                .seal_chunk(&buf[..read])
                .map_err(|err| format!("encode VMess WebSocket upload chunk: {err}"))?;
            write_websocket_binary_frame_to_stream(
                &mut upload_proxy,
                &encrypted,
                "write VMess websocket upload frame",
            )?;
            stats += read;
        }
        let _ = upload_proxy.shutdown(Shutdown::Write);
        Ok::<usize, String>(stats)
    });

    let download_result = {
        let mut ws_reader = WebSocketPayloadReader::new(proxy);
        let mut response =
            aead_tcp_response_reader_from_stream(&mut ws_reader, &session.request)
                .map_err(|err| format!("read VMess WebSocket AEAD response header: {err}"))?;
        let _response_header_len = response.response_header_len;

        let mut download_error = None;
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match response.read_chunk_from_stream(&mut ws_reader) {
                Ok(plain) => {
                    if plain.is_empty() {
                        continue;
                    }
                    inbound.write_all(&plain).map_err(|err| {
                        format!("write VMess WebSocket response to inbound: {err}")
                    })?;
                    stats.direct_to_client += plain.len();
                    metrics.add_download(plain.len());
                }
                Err(err) => {
                    let message = err.to_string();
                    if message.contains("early eof")
                        || message.contains("failed to fill whole buffer")
                        || message.contains("Connection reset")
                        || message.contains("connection reset")
                        || message.contains("timed out")
                    {
                        break;
                    }
                    download_error =
                        Some(format!("read VMess WebSocket response chunk: {message}"));
                    break;
                }
            }
        }
        if let Some(err) = download_error {
            Err(err)
        } else {
            Ok(())
        }
    };

    relay_done.store(true, Ordering::Relaxed);
    let _ = inbound.shutdown(Shutdown::Read);
    let _ = proxy.shutdown(Shutdown::Write);
    let upload_bytes = upload
        .join()
        .map_err(|_| "join VMess WebSocket upload relay thread failed".to_owned())??;
    download_result?;
    if upload_bytes > 0 {
        stats.client_to_direct += upload_bytes;
        metrics.add_upload(upload_bytes);
    }
    Ok(stats)
}

async fn relay_tcp_over_vmess_tls_aead_async(
    inbound: &mut TokioTcpStream,
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

async fn relay_tcp_over_vmess_websocket_tls_aead_async(
    inbound: &mut TokioTcpStream,
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

async fn read_vmess_websocket_tls_response_chunk(
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

#[allow(clippy::too_many_arguments)]
async fn relay_tcp_over_shadowsocks_v2ray_plugin_tls_ws(
    inbound: &mut TokioTcpStream,
    client: &mut AsyncResidentTlsClient,
    stop: Arc<AtomicBool>,
    target: &str,
    cipher: &str,
    password: &str,
    salt_len: usize,
    initial_payload: &[u8],
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let target_metadata = ShadowsocksMetadata::parse(target)
        .map_err(|err| format!("parse Shadowsocks v2ray-plugin target: {err}"))?;
    let mut first_plain = target_metadata
        .encode()
        .map_err(|err| format!("encode Shadowsocks v2ray-plugin target metadata: {err}"))?;
    first_plain.extend_from_slice(initial_payload);
    let mut client_salt = vec![0_u8; salt_len];
    fastrand::fill(&mut client_salt);
    let mut upload_encoder = AeadStreamCodec::new(cipher, password, &client_salt)
        .map_err(|err| format!("create Shadowsocks v2ray-plugin upload encoder: {err}"))?;
    let mut encrypted_initial = client_salt.clone();
    encrypted_initial.extend(
        upload_encoder
            .encrypt_chunk(&first_plain)
            .map_err(|err| format!("encode Shadowsocks v2ray-plugin initial frame: {err}"))?,
    );
    let mux_id = [0_u8, 0_u8];
    let mux_options = MuxFrameOptions::new(mux_id, "127.0.0.1", 0, "tcp");
    let mut mux_payload = mux_new_frame(&mux_options);
    mux_payload.extend(
        mux_data_frame(mux_id, &encrypted_initial)
            .map_err(|err| format!("build v2ray-plugin mux data frame: {err}"))?,
    );
    write_websocket_binary_frame_over_resident_tls_async(
        client,
        &mux_payload,
        "write Shadowsocks v2ray-plugin initial frame",
    )
    .await?;

    let mut stats = DirectTcpRelayStats::default();
    if !initial_payload.is_empty() {
        stats.client_to_direct += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }

    let mut mux_state = AsyncV2rayPluginMuxPayloadState::default();
    let mut download_decoder = None;
    let mut inbound_closed = false;
    let mut proxy_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            inbound_read = inbound.read(&mut inbound_buf), if !inbound_closed && !proxy_closed => {
                match inbound_read {
                    Ok(0) => {
                        inbound_closed = true;
                        let end_frame = mux_end_frame(mux_id);
                        let _ = write_websocket_binary_frame_over_resident_tls_async(
                            client,
                            &end_frame,
                            "write Shadowsocks v2ray-plugin mux end frame",
                        )
                        .await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        let encrypted = upload_encoder
                            .encrypt_chunk(&inbound_buf[..read])
                            .map_err(|err| format!("encrypt Shadowsocks v2ray-plugin upload chunk: {err}"))?;
                        let mux_frame = mux_data_frame(mux_id, &encrypted)
                            .map_err(|err| format!("build Shadowsocks v2ray-plugin upload mux frame: {err}"))?;
                        write_websocket_binary_frame_over_resident_tls_async(
                            client,
                            &mux_frame,
                            "write Shadowsocks v2ray-plugin upload frame",
                        )
                        .await?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        let end_frame = mux_end_frame(mux_id);
                        let _ = write_websocket_binary_frame_over_resident_tls_async(
                            client,
                            &end_frame,
                            "write Shadowsocks v2ray-plugin mux end frame",
                        )
                        .await;
                        last_activity = Instant::now();
                    }
                    Err(err) => {
                        return Err(format!("read inbound TCP for Shadowsocks v2ray-plugin upload: {err}"));
                    }
                }
            }
            proxy_chunk = read_shadowsocks_aead_chunk_from_v2ray_plugin_mux(
                client,
                &mut mux_state,
                mux_id,
                &mut download_decoder,
                cipher,
                password,
                salt_len,
            ), if !proxy_closed => {
                match proxy_chunk {
                    Ok(plain) => {
                        if !plain.is_empty() {
                            inbound
                                .write_all(&plain)
                                .await
                                .map_err(|err| format!("write Shadowsocks v2ray-plugin response to inbound: {err}"))?;
                            stats.direct_to_client += plain.len();
                            metrics.add_download(plain.len());
                        }
                        last_activity = Instant::now();
                    }
                    Err(err) => {
                        if is_graceful_shadowsocks_response_message(&err) {
                            proxy_closed = true;
                            let _ = inbound.shutdown().await;
                            last_activity = Instant::now();
                        } else {
                            return Err(err);
                        }
                    }
                }
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if proxy_closed {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident Shadowsocks v2ray-plugin relay idle timeout".to_owned());
                }
            }
        }
        if proxy_closed || (inbound_closed && proxy_closed) {
            break;
        }
    }
    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
async fn relay_tcp_over_trojan_websocket_inner_shadowsocks_tls(
    inbound: &mut TokioTcpStream,
    client: &mut AsyncResidentTlsClient,
    stop: Arc<AtomicBool>,
    target: &str,
    trojan_password: &str,
    inner_cipher: &str,
    inner_password: &str,
    initial_payload: &[u8],
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let spec = cipher_spec(inner_cipher)
        .map_err(|err| format!("resolve Trojan-Go inner Shadowsocks cipher: {err}"))?;
    let request =
        trojan_packet::tcp_request_header(trojan_password, "tcp", target, initial_payload)
            .map_err(|err| format!("build Trojan-Go inner Shadowsocks TCP request: {err}"))?;
    let mut client_salt = vec![0_u8; spec.salt_len];
    fastrand::fill(&mut client_salt);
    let mut upload_encoder = AeadStreamCodec::new(inner_cipher, inner_password, &client_salt)
        .map_err(|err| format!("create Trojan-Go inner Shadowsocks upload encoder: {err}"))?;
    let mut encrypted_initial = client_salt;
    encrypted_initial.extend(
        upload_encoder
            .encrypt_chunk(&request)
            .map_err(|err| format!("encode Trojan-Go inner Shadowsocks request: {err}"))?,
    );
    write_websocket_binary_frame_over_resident_tls_async(
        client,
        &encrypted_initial,
        "write Trojan-Go inner Shadowsocks websocket request",
    )
    .await?;

    let mut stats = DirectTcpRelayStats::default();
    if !initial_payload.is_empty() {
        stats.client_to_direct += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }

    let mut ws_state = AsyncWebSocketPayloadState::default();
    let mut download_decoder = None;
    let mut inbound_closed = false;
    let mut proxy_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];

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
                        let encrypted = upload_encoder
                            .encrypt_chunk(&inbound_buf[..read])
                            .map_err(|err| format!("encrypt Trojan-Go inner Shadowsocks upload chunk: {err}"))?;
                        write_websocket_binary_frame_over_resident_tls_async(
                            client,
                            &encrypted,
                            "write Trojan-Go inner Shadowsocks upload frame",
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
                        return Err(format!("read inbound TCP for Trojan-Go inner Shadowsocks upload: {err}"));
                    }
                }
            }
            proxy_chunk = read_shadowsocks_aead_chunk_from_websocket_tls(
                client,
                &mut ws_state,
                &mut download_decoder,
                inner_cipher,
                inner_password,
                spec.salt_len,
            ), if !proxy_closed => {
                match proxy_chunk {
                    Ok(plain) => {
                        if !plain.is_empty() {
                            inbound
                                .write_all(&plain)
                                .await
                                .map_err(|err| format!("write Trojan-Go inner Shadowsocks response to inbound: {err}"))?;
                            stats.direct_to_client += plain.len();
                            metrics.add_download(plain.len());
                        }
                        last_activity = Instant::now();
                    }
                    Err(err) => {
                        if is_graceful_shadowsocks_response_message(&err) {
                            proxy_closed = true;
                            let _ = inbound.shutdown().await;
                            last_activity = Instant::now();
                        } else {
                            return Err(err);
                        }
                    }
                }
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if proxy_closed || inbound_closed {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident Trojan-Go inner Shadowsocks relay idle timeout".to_owned());
                }
            }
        }
        if proxy_closed || (inbound_closed && proxy_closed) {
            break;
        }
    }
    Ok(stats)
}

fn is_graceful_shadowsocks_response_message(message: &str) -> bool {
    message.contains("early eof")
        || message.contains("failed to fill whole buffer")
        || message.contains("Connection reset")
        || message.contains("connection reset")
        || message.contains("timed out")
        || message.contains("broken pipe")
        || message.contains("close_notify")
}

fn is_graceful_vmess_response_message(message: &str) -> bool {
    message.contains("early eof")
        || message.contains("failed to fill whole buffer")
        || message.contains("Connection reset")
        || message.contains("connection reset")
        || message.contains("timed out")
        || message.contains("unexpected EOF")
        || message.contains("peer closed connection")
}

fn is_graceful_stream_close_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::BrokenPipe
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::NotConnected
    )
}

fn is_graceful_stream_close_message(message: &str) -> bool {
    message.contains("Broken pipe")
        || message.contains("Connection reset")
        || message.contains("Connection aborted")
        || message.contains("Not connected")
        || message.contains("broken pipe")
        || message.contains("connection reset")
        || message.contains("connection aborted")
        || message.contains("not connected")
}

fn is_graceful_tls_plain_close_error(err: &std::io::Error) -> bool {
    if is_graceful_stream_close_error(err) {
        return true;
    }
    let message = err.to_string();
    is_graceful_stream_close_message(&message)
        || message.contains("peer closed connection without sending TLS close_notify")
        || message.contains("without sending TLS close_notify")
}
