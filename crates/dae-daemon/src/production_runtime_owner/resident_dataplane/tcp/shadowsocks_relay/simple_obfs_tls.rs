use super::*;
#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp_over_shadowsocks_simple_obfs_tls_async(
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
) -> Result<DirectTcpRelayStats, String> {
    let target_metadata = ShadowsocksMetadata::parse(target)
        .map_err(|err| format!("parse Shadowsocks simple-obfs TLS target: {err}"))?;
    let mut first_plain = target_metadata
        .encode()
        .map_err(|err| format!("encode Shadowsocks simple-obfs TLS target metadata: {err}"))?;
    first_plain.extend_from_slice(initial_payload);
    let mut client_salt = vec![0_u8; salt_len];
    fastrand::fill(&mut client_salt);
    let mut encoder = AeadStreamCodec::new(cipher, password, &client_salt)
        .map_err(|err| format!("create Shadowsocks simple-obfs TLS upload encoder: {err}"))?;
    let mut encrypted_initial = client_salt.clone();
    encrypted_initial.extend(
        encoder
            .encrypt_chunk(&first_plain)
            .map_err(|err| format!("encode Shadowsocks simple-obfs TLS initial frame: {err}"))?,
    );
    let options = Sip003SimpleObfsTlsOptions::new(host);
    let obfs_request = simple_obfs_tls_client_hello_with_body(&options, &encrypted_initial)
        .map_err(|err| format!("build Shadowsocks simple-obfs TLS request: {err}"))?;
    proxy
        .write_all(&obfs_request)
        .await
        .map_err(|err| format!("write Shadowsocks simple-obfs TLS request: {err}"))?;
    let response_payload = read_simple_obfs_tls_response_payload_from_async_stream(proxy)
        .await
        .map_err(|err| format!("read Shadowsocks simple-obfs TLS response: {err}"))?;

    let mut stats = DirectTcpRelayStats::default();
    if !initial_payload.is_empty() {
        stats.client_to_direct += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }

    let mut proxy_reader = AsyncSimpleObfsTlsAppDataReader::new(response_payload, proxy);
    let mut server_salt = vec![0_u8; salt_len];
    proxy_reader
        .read_exact(&mut server_salt)
        .await
        .map_err(|err| format!("read Shadowsocks simple-obfs TLS server salt: {err}"))?;
    let mut decoder = AeadStreamCodec::new(cipher, password, &server_salt)
        .map_err(|err| format!("create Shadowsocks simple-obfs TLS response decoder: {err}"))?;
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
                        let encrypted = encoder.encrypt_chunk(&inbound_buf[..read]).map_err(|err| {
                            format!("encrypt Shadowsocks simple-obfs TLS upload chunk: {err}")
                        })?;
                        let frame = simple_obfs_tls_application_data_frame(&encrypted)?;
                        proxy_reader
                            .stream
                            .write_all(&frame)
                            .await
                            .map_err(|err| {
                                format!("write Shadowsocks simple-obfs TLS upload chunk: {err}")
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
                            "read inbound TCP for Shadowsocks simple-obfs TLS upload: {err}"
                        ));
                    }
                }
            }
            proxy_chunk = read_encrypted_chunk_from_async_stream(&mut proxy_reader, &mut decoder) => {
                match proxy_chunk {
                    Ok(plain) => {
                        if !plain.is_empty() {
                            inbound
                                .write_all(&plain)
                                .await
                                .map_err(|err| format!("write Shadowsocks simple-obfs TLS response: {err}"))?;
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
                        return Err(format!("read Shadowsocks simple-obfs TLS response: {message}"));
                    }
                }
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if inbound_closed {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident Shadowsocks simple-obfs TLS relay idle timeout".to_owned());
                }
            }
        }
    }
    Ok(stats)
}
