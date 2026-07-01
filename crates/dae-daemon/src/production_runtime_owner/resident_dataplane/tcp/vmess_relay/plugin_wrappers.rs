use super::*;
#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp_over_shadowsocks_v2ray_plugin_tls_ws(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
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
    let mut mux_payload = mux_new_frame(&mux_options)
        .map_err(|err| format!("build v2ray-plugin mux new frame: {err}"))?;
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
        if proxy_closed {
            break;
        }
    }
    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp_over_trojan_websocket_inner_shadowsocks_tls(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
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
        .map_err(|err| format!("resolve Trojan inner Shadowsocks cipher: {err}"))?;
    let request =
        trojan_packet::tcp_request_header(trojan_password, "tcp", target, initial_payload)
            .map_err(|err| format!("build Trojan inner Shadowsocks TCP request: {err}"))?;
    let mut client_salt = vec![0_u8; spec.salt_len];
    fastrand::fill(&mut client_salt);
    let mut upload_encoder = AeadStreamCodec::new(inner_cipher, inner_password, &client_salt)
        .map_err(|err| format!("create Trojan inner Shadowsocks upload encoder: {err}"))?;
    let mut encrypted_initial = client_salt;
    encrypted_initial.extend(
        upload_encoder
            .encrypt_chunk(&request)
            .map_err(|err| format!("encode Trojan inner Shadowsocks request: {err}"))?,
    );
    write_websocket_binary_frame_over_resident_tls_async(
        client,
        &encrypted_initial,
        "write Trojan inner Shadowsocks websocket request",
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
                            .map_err(|err| format!("encrypt Trojan inner Shadowsocks upload chunk: {err}"))?;
                        write_websocket_binary_frame_over_resident_tls_async(
                            client,
                            &encrypted,
                            "write Trojan inner Shadowsocks upload frame",
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
                        return Err(format!("read inbound TCP for Trojan inner Shadowsocks upload: {err}"));
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
                                .map_err(|err| format!("write Trojan inner Shadowsocks response to inbound: {err}"))?;
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
                    return Err("resident Trojan inner Shadowsocks relay idle timeout".to_owned());
                }
            }
        }
        if proxy_closed {
            break;
        }
    }
    Ok(stats)
}
