use super::*;
#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp_over_shadowsocks_2022_simple_obfs_http_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    proxy: &mut TokioTcpStream,
    stop: Arc<AtomicBool>,
    target: &str,
    cipher: &str,
    password: &str,
    salt_len: usize,
    initial_payload: &[u8],
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
        initial_payload,
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
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            inbound_read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match inbound_read {
                    Ok(0) => {
                        inbound_closed = true;
                        let _ = proxy_reader.stream.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        let encrypted = encoder.encode_chunk(&inbound_buf[..read]).map_err(|err| {
                            format!("encrypt Shadowsocks 2022 simple-obfs upload chunk: {err}")
                        })?;
                        proxy_reader
                            .stream
                            .write_all(&encrypted)
                            .await
                            .map_err(|err| {
                                format!("write Shadowsocks 2022 simple-obfs upload chunk: {err}")
                            })?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        let _ = proxy_reader.stream.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Err(err) => {
                        return Err(format!(
                            "read inbound TCP for Shadowsocks 2022 simple-obfs upload: {err}"
                        ));
                    }
                }
            }
            proxy_chunk = decoder.read_next_chunk_async(&mut proxy_reader) => {
                match proxy_chunk {
                    Ok(plain) => {
                        if !plain.is_empty() {
                            inbound.write_all(&plain).await.map_err(|err| {
                                format!("write Shadowsocks 2022 simple-obfs response to inbound: {err}")
                            })?;
                            stats.direct_to_client += plain.len();
                            metrics.add_download(plain.len());
                        }
                        last_activity = Instant::now();
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
            _ = time::sleep(Duration::from_millis(100)) => {
                if inbound_closed {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident Shadowsocks 2022 simple-obfs relay idle timeout".to_owned());
                }
            }
        }
    }
    Ok(stats)
}
