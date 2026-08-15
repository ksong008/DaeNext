use super::*;
// Shadowsocks AEAD relay keeps target, cipher, payload, and metrics context explicit.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp_over_shadowsocks_aead_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    proxy: &mut TokioTcpStream,
    stop: SharedResidentStopSignal,
    target: &str,
    cipher: &str,
    password: &str,
    salt_len: usize,
    initial_payload: Vec<u8>,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let target_metadata = ShadowsocksMetadata::parse(target)
        .map_err(|err| format!("parse Shadowsocks target: {err}"))?;
    let mut first_plain = target_metadata
        .encode()
        .map_err(|err| format!("encode Shadowsocks target metadata: {err}"))?;
    first_plain.extend_from_slice(&initial_payload);
    let mut client_salt = vec![0_u8; salt_len];
    fastrand::fill(&mut client_salt);
    let mut encoder = AeadStreamCodec::new(cipher, password, &client_salt)
        .map_err(|err| format!("create Shadowsocks upload encoder: {err}"))?;
    let mut initial = client_salt.clone();
    initial.extend(
        encoder
            .encrypt_chunk(&first_plain)
            .map_err(|err| format!("encode Shadowsocks initial TCP frame: {err}"))?,
    );
    proxy
        .write_all(&initial)
        .await
        .map_err(|err| format!("write Shadowsocks initial TCP frame: {err}"))?;

    let mut stats = DirectTcpRelayStats::default();
    if !initial_payload.is_empty() {
        stats.client_to_direct += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }
    drop((first_plain, initial, initial_payload, client_salt));

    let inbound_buf = Box::new([0_u8; SHADOWSOCKS_AEAD_TCP_BATCH_UPLOAD_BUFFER_SIZE]);
    let (progress, activity) = resident_duplex_progress();
    if stats.client_to_direct != 0 {
        progress.record_upload(stats.client_to_direct);
    }
    let (inbound_read, inbound_write) = tokio::io::split(&mut *inbound);
    let (proxy_read, proxy_write) = proxy.split();
    let upload_progress = progress.clone();
    let upload_stop = stop.clone();
    let upload = async move {
        let mut inbound_read = inbound_read;
        let mut proxy_write = proxy_write;
        let mut inbound_buf = inbound_buf;
        loop {
            let read = match inbound_read
                .read(encoder.batch_payload_buffer(inbound_buf.as_mut()))
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
                Err(err) => {
                    return Err(format!("read inbound TCP for Shadowsocks upload: {err}"));
                }
            };
            let wire_len = encoder
                .encrypt_batch_in_place(inbound_buf.as_mut(), read)
                .map_err(|err| format!("encrypt Shadowsocks upload batch: {err}"))?;
            if let Err(err) = proxy_write.write_all(&inbound_buf[..wire_len]).await {
                if upload_stop.load(Ordering::Acquire) || is_graceful_stream_close_error(&err) {
                    return Ok(());
                }
                return Err(format!("write Shadowsocks upload chunk: {err}"));
            }
            upload_progress.record_upload(read);
            metrics.add_upload(read);
        }
    };
    let download_progress = progress.clone();
    let download = async move {
        let mut proxy_read = proxy_read;
        let mut inbound_write = inbound_write;
        let mut server_salt = vec![0_u8; salt_len];
        proxy_read
            .read_exact(&mut server_salt)
            .await
            .map_err(|err| format!("read Shadowsocks server salt: {err}"))?;
        let mut decoder = AeadStreamCodec::new(cipher, password, &server_salt)
            .map_err(|err| format!("create Shadowsocks response decoder: {err}"))?;
        let mut frame_reader = AeadStreamFrameReader::new();
        loop {
            match frame_reader.read_batch(&mut proxy_read, &mut decoder).await {
                Ok(plain_len) => {
                    if plain_len != 0 {
                        inbound_write
                            .write_all(frame_reader.plaintext())
                            .await
                            .map_err(|err| {
                                format!("write Shadowsocks response to inbound: {err}")
                            })?;
                        metrics.add_download(plain_len);
                    }
                    download_progress.record_download(plain_len);
                    frame_reader.consume_plaintext();
                }
                Err(err) => {
                    let message = err.to_string();
                    if is_graceful_shadowsocks_response_message(&message) {
                        let _ = inbound_write.shutdown().await;
                        return Ok(());
                    }
                    return Err(format!("read Shadowsocks response chunk: {message}"));
                }
            }
        }
    };
    run_resident_duplex_relay(
        Box::pin(upload),
        Box::pin(download),
        stop,
        &progress,
        activity,
        "resident Shadowsocks relay idle timeout",
        Some(RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn continuous_shadowsocks_upload_does_not_block_response_salt() {
        let inbound_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_addr = inbound_listener.local_addr().unwrap();
        let mut client = TokioTcpStream::connect(inbound_addr).await.unwrap();
        let (mut inbound, _) = inbound_listener.accept().await.unwrap();

        let proxy_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let mut proxy = TokioTcpStream::connect(proxy_addr).await.unwrap();
        let (mut upstream, _) = proxy_listener.accept().await.unwrap();

        let cipher = "aes-128-gcm";
        let password = "resident-shadowsocks-aead-duplex";
        let client_salt = [7_u8; 16];
        let server_salt = [9_u8; 16];
        let mut server_encoder = AeadStreamCodec::new(cipher, password, &server_salt).unwrap();
        let metrics = ResidentDataplaneMetrics::default();
        let stop = ResidentStopSignal::shared();
        let relay = relay_tcp_over_shadowsocks_aead_async(
            &mut inbound,
            &mut proxy,
            stop.clone(),
            "example.com:443",
            cipher,
            password,
            client_salt.len(),
            Vec::new(),
            &metrics,
        );

        let peer = async move {
            let mut observed_salt = [0_u8; 16];
            upstream.read_exact(&mut observed_salt).await.unwrap();
            let mut request_decoder =
                AeadStreamCodec::new(cipher, password, &observed_salt).unwrap();
            let _target = dae_outbound::shadowsocks::read_encrypted_chunk_from_async_stream(
                &mut upstream,
                &mut request_decoder,
            )
            .await
            .unwrap();
            upstream.write_all(&server_salt).await.unwrap();
            let response = server_encoder.encrypt_chunk(b"response-ready").unwrap();
            upstream.write_all(&response).await.unwrap();

            let mut sent = 0_usize;
            while sent < 2 * 1024 * 1024 {
                client.write_all(&[0x5a; 16 * 1024]).await.unwrap();
                sent += 16 * 1024;
                if sent == 64 * 1024 {
                    let mut response = [0_u8; 14];
                    time::timeout(Duration::from_secs(1), client.read_exact(&mut response))
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(&response, b"response-ready");
                    stop.store(true, Ordering::Release);
                    break;
                }
            }
        };

        let (relay_result, ()) = tokio::join!(relay, peer);
        relay_result.unwrap();
    }
}
