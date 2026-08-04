use super::super::websocket::AsyncWebSocketPayloadChannelState;
use super::*;
#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp_over_shadowsocks_v2ray_plugin_tls_ws(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    client: &mut AsyncResidentTlsClient,
    stop: SharedResidentStopSignal,
    target: &str,
    cipher: &str,
    password: &str,
    salt_len: usize,
    initial_payload: Vec<u8>,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let target_metadata = ShadowsocksMetadata::parse(target)
        .map_err(|err| format!("parse Shadowsocks v2ray-plugin target: {err}"))?;
    let mut first_plain = target_metadata
        .encode()
        .map_err(|err| format!("encode Shadowsocks v2ray-plugin target metadata: {err}"))?;
    first_plain.extend_from_slice(&initial_payload);
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

    let (progress, activity) = resident_duplex_progress();
    if !initial_payload.is_empty() {
        progress.record_upload(initial_payload.len());
        metrics.add_upload(initial_payload.len());
    }
    drop((first_plain, encrypted_initial, mux_payload, initial_payload));

    let (control_tx, mut control_rx) = websocket_control_channel();
    let (inbound_read, inbound_write) = tokio::io::split(&mut *inbound);
    let (client_read, client_write) = tokio::io::split(&mut *client);
    let upload_progress = progress.clone();
    let upload = async move {
        let mut inbound_read = inbound_read;
        let mut client_write = client_write;
        let mut upload_buffer =
            Box::new([0_u8; MUX_DATA_FRAME_HEADER_BYTES + SHADOWSOCKS_AEAD_TCP_UPLOAD_BUFFER_SIZE]);
        loop {
            tokio::select! {
                biased;
                control = control_rx.recv() => {
                    let Some(control) = control else {
                        return Ok(());
                    };
                    write_websocket_control_response(
                        &mut client_write,
                        control,
                        "Shadowsocks v2ray-plugin websocket",
                    ).await?;
                }
                inbound_read = inbound_read.read(upload_encoder.chunk_payload_buffer(
                    &mut upload_buffer[MUX_DATA_FRAME_HEADER_BYTES..],
                )) => {
                    let read = match inbound_read {
                        Ok(0) => {
                            let mut end_frame = mux_end_frame(mux_id);
                            write_websocket_binary_frame_in_place_to_async_stream(
                                &mut client_write,
                                &mut end_frame,
                                "write Shadowsocks v2ray-plugin mux end frame",
                            ).await?;
                            return Ok(());
                        }
                        Ok(read) => read,
                        Err(err) if is_graceful_stream_close_error(&err) => {
                            let mut end_frame = mux_end_frame(mux_id);
                            write_websocket_binary_frame_in_place_to_async_stream(
                                &mut client_write,
                                &mut end_frame,
                                "write Shadowsocks v2ray-plugin mux end frame",
                            ).await?;
                            return Ok(());
                        }
                        Err(err) => return Err(format!(
                            "read inbound TCP for Shadowsocks v2ray-plugin upload: {err}"
                        )),
                    };
                    let encrypted_len = upload_encoder
                        .encrypt_chunk_in_place(
                            &mut upload_buffer[MUX_DATA_FRAME_HEADER_BYTES..],
                            read,
                        )
                        .map_err(|err| format!(
                            "encrypt Shadowsocks v2ray-plugin upload chunk: {err}"
                        ))?;
                    let mux_header = mux_data_frame_header(mux_id, encrypted_len).map_err(|err| {
                        format!("build Shadowsocks v2ray-plugin upload mux frame: {err}")
                    })?;
                    upload_buffer[..MUX_DATA_FRAME_HEADER_BYTES].copy_from_slice(&mux_header);
                    let mux_frame_len = MUX_DATA_FRAME_HEADER_BYTES + encrypted_len;
                    write_websocket_binary_frame_in_place_to_async_stream(
                        &mut client_write,
                        &mut upload_buffer[..mux_frame_len],
                        "write Shadowsocks v2ray-plugin upload frame",
                    ).await?;
                    upload_progress.record_upload(read);
                    metrics.add_upload(read);
                }
            }
        }
    };
    let download_progress = progress.clone();
    let download = async move {
        let mut client_read = client_read;
        let mut inbound_write = inbound_write;
        let mut mux_state = AsyncV2rayPluginMuxPayloadState::new(control_tx);
        let mut download_decoder = None;
        let mut response_buffer = Box::new([0_u8; SHADOWSOCKS_AEAD_TCP_DOWNLOAD_BUFFER_SIZE]);
        loop {
            match read_shadowsocks_aead_chunk_in_place_from_v2ray_plugin_mux(
                &mut client_read,
                &mut mux_state,
                mux_id,
                &mut download_decoder,
                ShadowsocksAeadResponseParameters {
                    cipher,
                    password,
                    salt_len,
                },
                response_buffer.as_mut(),
            )
            .await
            {
                Ok(plain_len) => {
                    if plain_len != 0 {
                        inbound_write
                            .write_all(&response_buffer[..plain_len])
                            .await
                            .map_err(|err| {
                                format!("write Shadowsocks v2ray-plugin response to inbound: {err}")
                            })?;
                        download_progress.record_download(plain_len);
                        metrics.add_download(plain_len);
                    }
                }
                Err(err) if is_graceful_shadowsocks_response_message(&err) => {
                    let _ = inbound_write.shutdown().await;
                    return Ok(());
                }
                Err(err) => return Err(err),
            }
        }
    };

    run_resident_duplex_relay(
        Box::pin(upload),
        Box::pin(download),
        stop,
        &progress,
        activity,
        "resident Shadowsocks v2ray-plugin relay idle timeout",
        Some(RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp_over_trojan_websocket_inner_shadowsocks_tls(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    client: &mut AsyncResidentTlsClient,
    stop: SharedResidentStopSignal,
    target: &str,
    trojan_password: &str,
    inner_cipher: &str,
    inner_password: &str,
    initial_payload: Vec<u8>,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let spec = cipher_spec(inner_cipher)
        .map_err(|err| format!("resolve Trojan inner Shadowsocks cipher: {err}"))?;
    let request =
        trojan_packet::tcp_request_header(trojan_password, "tcp", target, &initial_payload)
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

    let (progress, activity) = resident_duplex_progress();
    if !initial_payload.is_empty() {
        progress.record_upload(initial_payload.len());
        metrics.add_upload(initial_payload.len());
    }
    drop((request, encrypted_initial, initial_payload));

    let (control_tx, mut control_rx) = websocket_control_channel();
    let (inbound_read, inbound_write) = tokio::io::split(&mut *inbound);
    let (client_read, client_write) = tokio::io::split(&mut *client);
    let upload_progress = progress.clone();
    let upload = async move {
        let mut inbound_read = inbound_read;
        let mut client_write = client_write;
        let mut upload_buffer = Box::new([0_u8; SHADOWSOCKS_AEAD_TCP_UPLOAD_BUFFER_SIZE]);
        loop {
            tokio::select! {
                biased;
                control = control_rx.recv() => {
                    let Some(control) = control else {
                        return Ok(());
                    };
                    write_websocket_control_response(
                        &mut client_write,
                        control,
                        "Trojan inner Shadowsocks websocket",
                    ).await?;
                }
                inbound_read = inbound_read.read(upload_encoder.chunk_payload_buffer(
                    upload_buffer.as_mut(),
                )) => {
                    let read = match inbound_read {
                        Ok(0) => {
                            return Ok(());
                        }
                        Ok(read) => read,
                        Err(err) if is_graceful_stream_close_error(&err) => {
                            return Ok(());
                        }
                        Err(err) => return Err(format!(
                            "read inbound TCP for Trojan inner Shadowsocks upload: {err}"
                        )),
                    };
                    let wire_len = upload_encoder
                        .encrypt_chunk_in_place(upload_buffer.as_mut(), read)
                        .map_err(|err| format!(
                            "encrypt Trojan inner Shadowsocks upload chunk: {err}"
                        ))?;
                    write_websocket_binary_frame_in_place_to_async_stream(
                        &mut client_write,
                        &mut upload_buffer[..wire_len],
                        "write Trojan inner Shadowsocks upload frame",
                    ).await?;
                    upload_progress.record_upload(read);
                    metrics.add_upload(read);
                }
            }
        }
    };
    let download_progress = progress.clone();
    let download = async move {
        let mut client_read = client_read;
        let mut inbound_write = inbound_write;
        let mut ws_state = AsyncWebSocketPayloadChannelState::new(control_tx);
        let mut download_decoder = None;
        let mut response_buffer = Box::new([0_u8; SHADOWSOCKS_AEAD_TCP_DOWNLOAD_BUFFER_SIZE]);
        loop {
            match read_shadowsocks_aead_chunk_in_place_from_websocket_tls(
                &mut client_read,
                &mut ws_state,
                &mut download_decoder,
                ShadowsocksAeadResponseParameters {
                    cipher: inner_cipher,
                    password: inner_password,
                    salt_len: spec.salt_len,
                },
                response_buffer.as_mut(),
            )
            .await
            {
                Ok(plain_len) => {
                    if plain_len != 0 {
                        inbound_write
                            .write_all(&response_buffer[..plain_len])
                            .await
                            .map_err(|err| {
                                format!("write Trojan inner Shadowsocks response to inbound: {err}")
                            })?;
                        download_progress.record_download(plain_len);
                        metrics.add_download(plain_len);
                    }
                }
                Err(err) if is_graceful_shadowsocks_response_message(&err) => {
                    let _ = inbound_write.shutdown().await;
                    return Ok(());
                }
                Err(err) => return Err(err),
            }
        }
    };

    run_resident_duplex_relay(
        Box::pin(upload),
        Box::pin(download),
        stop,
        &progress,
        activity,
        "resident Trojan inner Shadowsocks relay idle timeout",
        Some(RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT),
    )
    .await
}
