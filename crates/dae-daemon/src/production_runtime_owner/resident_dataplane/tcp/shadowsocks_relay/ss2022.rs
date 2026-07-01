use super::*;
#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp_over_shadowsocks_2022_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    proxy: &mut TokioTcpStream,
    stop: Arc<AtomicBool>,
    target: &str,
    cipher: &str,
    password: &str,
    salt_len: usize,
    initial_payload: &[u8],
    metrics: &ResidentDataplaneMetrics,
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
    .map_err(|err| format!("encode Shadowsocks 2022 initial TCP frame: {err}"))?;
    proxy
        .write_all(&initial)
        .await
        .map_err(|err| format!("write Shadowsocks 2022 initial TCP frame: {err}"))?;
    let mut stats = DirectTcpRelayStats::default();
    if !initial_payload.is_empty() {
        stats.client_to_direct += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }

    let mut inbound_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut decoder = None;

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            inbound_read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match inbound_read {
                    Ok(0) => {
                        inbound_closed = true;
                        let _ = proxy.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        let encrypted = encoder
                            .encode_chunk(&inbound_buf[..read])
                            .map_err(|err| format!("encrypt Shadowsocks 2022 upload chunk: {err}"))?;
                        proxy
                            .write_all(&encrypted)
                            .await
                            .map_err(|err| format!("write Shadowsocks 2022 upload chunk: {err}"))?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        let _ = proxy.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Err(err) => {
                        return Err(format!(
                            "read inbound TCP for Shadowsocks 2022 upload: {err}"
                        ));
                    }
                }
            }
            proxy_plain = read_shadowsocks_2022_proxy_plain_async(
                proxy,
                &mut decoder,
                cipher,
                password,
                &client_salt,
            ) => {
                match proxy_plain {
                    Ok(Shadowsocks2022ProxyPlain::Initial {
                        decoder: next_decoder,
                        payload,
                    }) => {
                        decoder = Some(next_decoder);
                        if !payload.is_empty() {
                            inbound
                                .write_all(&payload)
                                .await
                                .map_err(|err| format!("write Shadowsocks 2022 initial response to inbound: {err}"))?;
                            stats.direct_to_client += payload.len();
                            metrics.add_download(payload.len());
                        }
                        last_activity = Instant::now();
                    }
                    Ok(Shadowsocks2022ProxyPlain::Chunk(plain)) => {
                        if !plain.is_empty() {
                            inbound
                                .write_all(&plain)
                                .await
                                .map_err(|err| format!("write Shadowsocks 2022 response to inbound: {err}"))?;
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
                        return Err(format!("read Shadowsocks 2022 response chunk: {message}"));
                    }
                }
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if inbound_closed {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident Shadowsocks 2022 relay idle timeout".to_owned());
                }
            }
        }
    }
    Ok(stats)
}

enum Shadowsocks2022ProxyPlain {
    Initial {
        decoder: Ss2022TcpServerStreamDecoder,
        payload: Vec<u8>,
    },
    Chunk(Vec<u8>),
}

async fn read_shadowsocks_2022_proxy_plain_async(
    proxy: &mut TokioTcpStream,
    decoder: &mut Option<Ss2022TcpServerStreamDecoder>,
    cipher: &str,
    password: &str,
    client_salt: &[u8],
) -> Result<Shadowsocks2022ProxyPlain, String> {
    if let Some(decoder) = decoder.as_mut() {
        return decoder
            .read_next_chunk_async(proxy)
            .await
            .map(Shadowsocks2022ProxyPlain::Chunk)
            .map_err(|err| err.to_string());
    }

    let (decoder, start) =
        ss2022_tcp_server_stream_decoder_async(proxy, cipher, password, client_salt)
            .await
            .map_err(|err| format!("read Shadowsocks 2022 server stream header: {err}"))?;
    if !start.request_salt_echo_validated {
        return Err("Shadowsocks 2022 server response did not echo request salt".to_owned());
    }
    Ok(Shadowsocks2022ProxyPlain::Initial {
        decoder,
        payload: start.payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shadowsocks_2022_relay_uploads_client_data_before_server_response() {
        let cipher = "2022-blake3-aes-128-gcm";
        let password = "AQIDBAUGBwgJCgsMDQ4PEA==";
        let target = "example.com:80";
        let request = b"HEAD /generate_204 HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let expected_request = request.clone();

        std::thread::spawn(move || {
            let result = (|| -> Result<(), String> {
                let (mut stream, _) = listener.accept().map_err(|err| err.to_string())?;
                let observed =
                    dae_outbound::shadowsocks::read_ss2022_tcp_client_request_from_stream(
                        &mut stream,
                        cipher,
                        password,
                        expected_request.len(),
                    )
                    .map_err(|err| err.to_string())?;
                if observed.target != target {
                    return Err(format!("target mismatch: {}", observed.target));
                }
                if observed.payload != expected_request {
                    return Err("payload mismatch".to_owned());
                }
                Ok(())
            })();
            let _ = tx.send(result);
        });

        let mut proxy = TokioTcpStream::connect(endpoint).await.unwrap();
        let (mut client_side, mut relay_side) = tokio::io::duplex(64 * 1024);
        let stop = Arc::new(AtomicBool::new(false));
        let relay_stop = Arc::clone(&stop);
        let metrics = ResidentDataplaneMetrics::default();
        let relay = tokio::spawn(async move {
            relay_tcp_over_shadowsocks_2022_async(
                &mut relay_side,
                &mut proxy,
                relay_stop,
                target,
                cipher,
                password,
                16,
                &[],
                &metrics,
            )
            .await
        });

        client_side.write_all(&request).await.unwrap();
        client_side.flush().await.unwrap();
        let observed = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::task::spawn_blocking(move || rx.recv().unwrap()),
        )
        .await
        .expect("server observed client data before response")
        .unwrap();
        observed.unwrap();
        stop.store(true, Ordering::Relaxed);
        drop(client_side);
        let _ = tokio::time::timeout(Duration::from_secs(2), relay).await;
    }
}
