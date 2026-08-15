use super::*;
#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp_over_shadowsocks_2022_simple_obfs_http_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    proxy: &mut TokioTcpStream,
    stop: SharedResidentStopSignal,
    target: &str,
    cipher: &str,
    password: &str,
    salt_len: usize,
    initial_payload: Vec<u8>,
    metrics: &ResidentDataplaneMetrics,
    host: &str,
    path: &str,
) -> Result<DirectTcpRelayStats, String> {
    let mut client_salt = vec![0_u8; salt_len];
    fastrand::fill(&mut client_salt);
    let (mut encoder, initial) = ss2022_tcp_client_stream_encoder(
        cipher,
        password,
        &client_salt,
        target,
        &initial_payload,
        ss2022_tcp_unix_timestamp_now(),
    )
    .map_err(|err| format!("encode Shadowsocks 2022 simple-obfs initial TCP frame: {err}"))?;
    let options = Sip003SimpleObfsHttpOptions::new(host, path);
    let obfs_request = simple_obfs_http_request_with_body(&options, &initial);
    proxy
        .write_all(&obfs_request)
        .await
        .map_err(|err| format!("write Shadowsocks 2022 simple-obfs request: {err}"))?;
    let (response_head, response_leftover) = read_http_head_and_leftover_from_async_stream(proxy)
        .await
        .map_err(|err| format!("read Shadowsocks 2022 simple-obfs response head: {err}"))?;
    validate_simple_obfs_http_response_status(&response_head)
        .map_err(|err| format!("validate Shadowsocks 2022 simple-obfs response status: {err}"))?;

    let mut stats = DirectTcpRelayStats::default();
    if !initial_payload.is_empty() {
        stats.client_to_direct += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }
    drop((initial, obfs_request, response_head, initial_payload));

    let mut proxy_reader = AsyncPrefixTcpReader::new(response_leftover, proxy);
    let (mut decoder, start) =
        ss2022_tcp_server_stream_decoder_async(&mut proxy_reader, cipher, password, &client_salt)
            .await
            .map_err(|err| {
                format!("read Shadowsocks 2022 simple-obfs server stream header: {err}")
            })?;
    if !start.request_salt_echo_validated {
        return Err(
            "Shadowsocks 2022 simple-obfs server response did not echo request salt".to_owned(),
        );
    }
    if !start.payload.is_empty() {
        inbound.write_all(&start.payload).await.map_err(|err| {
            format!("write Shadowsocks 2022 simple-obfs initial response to inbound: {err}")
        })?;
        stats.direct_to_client += start.payload.len();
        metrics.add_download(start.payload.len());
    }

    let mut inbound_closed = false;
    let mut inbound_buf = Box::new([0_u8; SS2022_TCP_RELAY_UPLOAD_BUFFER_SIZE]);
    let mut response_buffer = Vec::with_capacity(SS2022_TCP_RELAY_PAYLOAD_SIZE + 16);
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
            inbound_read = inbound.read(encoder.chunk_payload_buffer(inbound_buf.as_mut())), if !inbound_closed => {
                match inbound_read {
                    Ok(0) => {
                        inbound_closed = true;
                        let _ = proxy_reader.stream.shutdown().await;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                        reset_resident_relay_idle_deadline(
                            close_drain_deadline.as_mut(),
                            RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT,
                        );
                        close_drain_active = true;
                    }
                    Ok(read) => {
                        let wire_len = encoder.encode_chunk_in_place(inbound_buf.as_mut(), read).map_err(|err| {
                            format!("encrypt Shadowsocks 2022 simple-obfs upload chunk: {err}")
                        })?;
                        proxy_reader
                            .stream
                            .write_all(&inbound_buf[..wire_len])
                            .await
                            .map_err(|err| {
                                format!("write Shadowsocks 2022 simple-obfs upload chunk: {err}")
                            })?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        let _ = proxy_reader.stream.shutdown().await;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                        reset_resident_relay_idle_deadline(
                            close_drain_deadline.as_mut(),
                            RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT,
                        );
                        close_drain_active = true;
                    }
                    Err(err) => {
                        return Err(format!(
                            "read inbound TCP for Shadowsocks 2022 simple-obfs upload: {err}"
                        ));
                    }
                }
            }
            proxy_chunk = decoder.read_next_chunk_in_place_async(&mut proxy_reader, &mut response_buffer) => {
                match proxy_chunk {
                    Ok(plain_len) => {
                        if plain_len != 0 {
                            inbound.write_all(&response_buffer[..plain_len]).await.map_err(|err| {
                                format!("write Shadowsocks 2022 simple-obfs response to inbound: {err}")
                            })?;
                            stats.direct_to_client += plain_len;
                            metrics.add_download(plain_len);
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
                        if is_graceful_shadowsocks_response_message(&message) {
                            break;
                        }
                        return Err(format!(
                            "read Shadowsocks 2022 simple-obfs response chunk: {message}"
                        ));
                    }
                }
            }
            _ = &mut close_drain_deadline, if close_drain_active => break,
            _ = &mut idle_deadline => {
                return Err("resident Shadowsocks 2022 simple-obfs relay idle timeout".to_owned());
            }
        }
    }
    Ok(stats)
}
