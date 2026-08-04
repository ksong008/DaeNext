use super::*;
#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp_over_shadowsocks_2022_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    proxy: &mut TokioTcpStream,
    stop: SharedResidentStopSignal,
    target: &str,
    cipher: &str,
    password: &str,
    salt_len: usize,
    initial_payload: Vec<u8>,
    metrics: &ResidentDataplaneMetrics,
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
    drop((initial, initial_payload));

    let (mut inbound_reader, mut inbound_writer) = tokio::io::split(inbound);
    let (mut proxy_reader, mut proxy_writer) = tokio::io::split(proxy);
    let upload_stop = Arc::clone(&stop);
    let download_stop = Arc::clone(&stop);
    let upload = relay_shadowsocks_2022_upload_async(
        &mut inbound_reader,
        &mut proxy_writer,
        upload_stop,
        &mut encoder,
        metrics,
    );
    let download = relay_shadowsocks_2022_download_async(
        &mut proxy_reader,
        &mut inbound_writer,
        download_stop,
        cipher,
        password,
        &client_salt,
        metrics,
    );
    tokio::pin!(upload);
    tokio::pin!(download);
    let mut upload_done = false;

    loop {
        tokio::select! {
            upload_result = &mut upload, if !upload_done => {
                stats.client_to_direct += upload_result?;
                upload_done = true;
            }
            download_result = &mut download => {
                stats.direct_to_client += download_result?;
                break;
            }
        }
    }
    Ok(stats)
}

async fn relay_shadowsocks_2022_upload_async<R, W>(
    inbound: &mut R,
    proxy: &mut W,
    stop: SharedResidentStopSignal,
    encoder: &mut Ss2022TcpClientStreamEncoder,
    metrics: &ResidentDataplaneMetrics,
) -> Result<usize, String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut uploaded = 0_usize;
    let mut inbound_buf = Box::new([0_u8; SS2022_TCP_RELAY_UPLOAD_BUFFER_SIZE]);
    let mut stop_listener = stop.listener();
    loop {
        tokio::select! {
            _ = stop_listener.cancelled() => {
                let _ = proxy.shutdown().await;
                break;
            }
            inbound_read = inbound.read(encoder.chunk_payload_buffer(inbound_buf.as_mut())) => {
                match inbound_read {
                    Ok(0) => {
                        let _ = proxy.shutdown().await;
                        break;
                    }
                    Ok(read) => {
                        let wire_len = encoder
                            .encode_chunk_in_place(inbound_buf.as_mut(), read)
                            .map_err(|err| format!("encrypt Shadowsocks 2022 upload chunk: {err}"))?;
                        proxy
                            .write_all(&inbound_buf[..wire_len])
                            .await
                            .map_err(|err| format!("write Shadowsocks 2022 upload chunk: {err}"))?;
                        uploaded += read;
                        metrics.add_upload(read);
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        let _ = proxy.shutdown().await;
                        break;
                    }
                    Err(err) => {
                        return Err(format!(
                            "read inbound TCP for Shadowsocks 2022 upload: {err}"
                        ));
                    }
                }
            }
        }
    }
    Ok(uploaded)
}

async fn relay_shadowsocks_2022_download_async<R, W>(
    proxy: &mut R,
    inbound: &mut W,
    stop: SharedResidentStopSignal,
    cipher: &str,
    password: &str,
    client_salt: &[u8],
    metrics: &ResidentDataplaneMetrics,
) -> Result<usize, String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut downloaded = 0_usize;
    let mut decoder = None;
    let mut response_buffer = Vec::with_capacity(SS2022_TCP_RELAY_PAYLOAD_SIZE + 16);
    let mut stop_listener = stop.listener();
    let idle_deadline = resident_relay_idle_deadline(RESIDENT_TCP_IDLE_TIMEOUT);
    tokio::pin!(idle_deadline);
    loop {
        let proxy_plain = tokio::select! {
            _ = stop_listener.cancelled() => break,
            result = read_shadowsocks_2022_proxy_plain_async(
                proxy,
                &mut decoder,
                cipher,
                password,
                client_salt,
                &mut response_buffer,
            ) => match result {
                Ok(plain) => plain,
                Err(err) => {
                    let message = err.to_string();
                    if is_graceful_shadowsocks_response_message(&message) {
                        break;
                    }
                    return Err(format!("read Shadowsocks 2022 response chunk: {message}"));
                }
            },
            _ = &mut idle_deadline => {
                return Err("resident Shadowsocks 2022 relay idle timeout".to_owned());
            }
        };
        match proxy_plain {
            Shadowsocks2022ProxyPlain::Initial {
                decoder: next_decoder,
                payload,
            } => {
                decoder = Some(next_decoder);
                if !payload.is_empty() {
                    inbound.write_all(&payload).await.map_err(|err| {
                        format!("write Shadowsocks 2022 initial response to inbound: {err}")
                    })?;
                    downloaded += payload.len();
                    metrics.add_download(payload.len());
                }
            }
            Shadowsocks2022ProxyPlain::Chunk(plain_len) => {
                if plain_len != 0 {
                    inbound
                        .write_all(&response_buffer[..plain_len])
                        .await
                        .map_err(|err| {
                            format!("write Shadowsocks 2022 response to inbound: {err}")
                        })?;
                    downloaded += plain_len;
                    metrics.add_download(plain_len);
                }
            }
        }
        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
    }
    Ok(downloaded)
}

enum Shadowsocks2022ProxyPlain {
    Initial {
        decoder: Ss2022TcpServerStreamDecoder,
        payload: Vec<u8>,
    },
    Chunk(usize),
}

async fn read_shadowsocks_2022_proxy_plain_async(
    proxy: &mut (impl AsyncRead + Unpin),
    decoder: &mut Option<Ss2022TcpServerStreamDecoder>,
    cipher: &str,
    password: &str,
    client_salt: &[u8],
    response_buffer: &mut Vec<u8>,
) -> Result<Shadowsocks2022ProxyPlain, String> {
    if let Some(decoder) = decoder.as_mut() {
        return decoder
            .read_next_chunk_in_place_async(proxy, response_buffer)
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

    #[tokio::test(flavor = "current_thread")]
    async fn shadowsocks_2022_idle_relay_stops_without_polling() {
        let cipher = "2022-blake3-aes-128-gcm";
        let password = "AQIDBAUGBwgJCgsMDQ4PEA==";
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let mut proxy = TokioTcpStream::connect(endpoint).await.unwrap();
        let (_upstream, _) = listener.accept().await.unwrap();
        let (_client_side, mut relay_side) = tokio::io::duplex(64 * 1024);
        let stop = ResidentStopSignal::shared();
        let relay_stop = Arc::clone(&stop);
        let metrics = ResidentDataplaneMetrics::default();
        let relay = tokio::spawn(async move {
            relay_tcp_over_shadowsocks_2022_async(
                &mut relay_side,
                &mut proxy,
                relay_stop,
                "example.com:443",
                cipher,
                password,
                16,
                Vec::new(),
                &metrics,
            )
            .await
        });

        tokio::task::yield_now().await;
        stop.store(true, Ordering::Relaxed);
        let result = time::timeout(Duration::from_millis(50), relay)
            .await
            .expect("SS2022 relay did not observe stop broadcast")
            .unwrap();
        assert!(result.is_ok());
    }

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
        let stop = ResidentStopSignal::shared();
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
                Vec::new(),
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

    #[tokio::test]
    async fn shadowsocks_2022_relay_keeps_downloading_after_client_half_close() {
        let cipher = "2022-blake3-aes-128-gcm";
        let password = "AQIDBAUGBwgJCgsMDQ4PEA==";
        let target = "example.com:80";
        let request = b"GET /large HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let response_payload = vec![0x42; 32 * 1024];
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let expected_request = request.clone();
        let expected_response = response_payload.clone();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request_bytes = Vec::new();
            std::io::Read::read_to_end(&mut stream, &mut request_bytes).unwrap();
            let request_salt = request_bytes[..16].to_vec();
            let observed = dae_outbound::shadowsocks::decode_client_request(
                cipher,
                password,
                &request_bytes,
                expected_request.len(),
            )
            .unwrap();
            assert_eq!(observed.target, target);
            assert_eq!(observed.payload, expected_request);
            std::thread::sleep(Duration::from_millis(250));
            let server_salt = [7_u8; 16];
            let response = dae_outbound::shadowsocks::encode_ss2022_tcp_server_response(
                cipher,
                password,
                &server_salt,
                &request_salt,
                &expected_response,
                dae_outbound::shadowsocks::ss2022_tcp_unix_timestamp_now(),
            )
            .unwrap();
            std::io::Write::write_all(&mut stream, &response).unwrap();
        });

        let mut proxy = TokioTcpStream::connect(endpoint).await.unwrap();
        let (mut client_side, mut relay_side) = tokio::io::duplex(128 * 1024);
        let stop = ResidentStopSignal::shared();
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
                Vec::new(),
                &metrics,
            )
            .await
        });

        client_side.write_all(&request).await.unwrap();
        client_side.shutdown().await.unwrap();
        let mut observed = vec![0_u8; response_payload.len()];
        tokio::time::timeout(
            Duration::from_secs(3),
            client_side.read_exact(&mut observed),
        )
        .await
        .expect("relay returned delayed response after upload EOF")
        .unwrap();
        assert_eq!(observed, response_payload);
        stop.store(true, Ordering::Relaxed);
        let relay_result = tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .unwrap()
            .unwrap();
        assert!(relay_result.unwrap().direct_to_client >= response_payload.len());
    }
}
