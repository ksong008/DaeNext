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

    let mut inbound_buf = [0_u8; 16 * 1024];
    let inbound_closed = drain_pending_shadowsocks_aead_upload(
        inbound,
        proxy,
        &mut encoder,
        &mut stats,
        metrics,
        &mut inbound_buf,
    )
    .await?;

    let mut server_salt = vec![0_u8; salt_len];
    proxy
        .read_exact(&mut server_salt)
        .await
        .map_err(|err| format!("read Shadowsocks server salt: {err}"))?;
    let mut decoder = AeadStreamCodec::new(cipher, password, &server_salt)
        .map_err(|err| format!("create Shadowsocks response decoder: {err}"))?;
    let (progress, activity) = resident_duplex_progress();
    if stats.client_to_direct != 0 {
        progress.record_upload(stats.client_to_direct);
    }
    let (inbound_read, inbound_write) = tokio::io::split(&mut *inbound);
    let (proxy_read, mut proxy_write) = proxy.split();
    let upload_progress = progress.clone();
    let upload = async move {
        if inbound_closed {
            let _ = proxy_write.shutdown().await;
            return Ok(());
        }
        let mut inbound_read = inbound_read;
        let mut proxy_write = proxy_write;
        loop {
            let read = match inbound_read.read(&mut inbound_buf).await {
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
            let encrypted = encoder
                .encrypt_chunk(&inbound_buf[..read])
                .map_err(|err| format!("encrypt Shadowsocks upload chunk: {err}"))?;
            proxy_write
                .write_all(&encrypted)
                .await
                .map_err(|err| format!("write Shadowsocks upload chunk: {err}"))?;
            upload_progress.record_upload(read);
            metrics.add_upload(read);
        }
    };
    let download_progress = progress.clone();
    let download = async move {
        let mut proxy_read = proxy_read;
        let mut inbound_write = inbound_write;
        loop {
            match read_encrypted_chunk_from_async_stream(&mut proxy_read, &mut decoder).await {
                Ok(plain) => {
                    if !plain.is_empty() {
                        inbound_write.write_all(&plain).await.map_err(|err| {
                            format!("write Shadowsocks response to inbound: {err}")
                        })?;
                        metrics.add_download(plain.len());
                    }
                    download_progress.record_download(plain.len());
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

async fn drain_pending_shadowsocks_aead_upload(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    proxy: &mut TokioTcpStream,
    encoder: &mut AeadStreamCodec,
    stats: &mut DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
    inbound_buf: &mut [u8],
) -> Result<bool, String> {
    let mut inbound_closed = false;
    loop {
        match time::timeout(Duration::from_millis(10), inbound.read(inbound_buf)).await {
            Ok(Ok(0)) => {
                inbound_closed = true;
                let _ = proxy.shutdown().await;
                break;
            }
            Ok(Ok(read)) => {
                let encrypted = encoder
                    .encrypt_chunk(&inbound_buf[..read])
                    .map_err(|err| format!("encrypt Shadowsocks pending upload chunk: {err}"))?;
                proxy
                    .write_all(&encrypted)
                    .await
                    .map_err(|err| format!("write Shadowsocks pending upload chunk: {err}"))?;
                stats.client_to_direct += read;
                metrics.add_upload(read);
            }
            Ok(Err(err)) if is_graceful_stream_close_error(&err) => {
                inbound_closed = true;
                let _ = proxy.shutdown().await;
                break;
            }
            Ok(Err(err)) => {
                return Err(format!(
                    "read inbound TCP for pending Shadowsocks upload: {err}"
                ));
            }
            Err(_) => break,
        }
    }
    Ok(inbound_closed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn pending_shadowsocks_aead_upload_is_flushed_before_response_salt() {
        let pending_payload = b"split-client-hello-tail";

        let inbound_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_addr = inbound_listener.local_addr().unwrap();
        let mut client = TokioTcpStream::connect(inbound_addr).await.unwrap();
        let (mut inbound, _) = inbound_listener.accept().await.unwrap();
        client.write_all(pending_payload).await.unwrap();

        let proxy_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let mut proxy = TokioTcpStream::connect(proxy_addr).await.unwrap();
        let (mut upstream, _) = proxy_listener.accept().await.unwrap();

        let cipher = "aes-128-gcm";
        let password = "resident-shadowsocks-aead-pending-upload";
        let salt = [7_u8; 16];
        let mut encoder = AeadStreamCodec::new(cipher, password, &salt).unwrap();
        let mut decoder = AeadStreamCodec::new(cipher, password, &salt).unwrap();
        let metrics = ResidentDataplaneMetrics::default();
        let mut stats = DirectTcpRelayStats::default();
        let mut inbound_buf = [0_u8; 1024];

        let inbound_closed = drain_pending_shadowsocks_aead_upload(
            &mut inbound,
            &mut proxy,
            &mut encoder,
            &mut stats,
            &metrics,
            &mut inbound_buf,
        )
        .await
        .unwrap();

        assert!(!inbound_closed);
        assert_eq!(stats.client_to_direct, pending_payload.len());
        assert_eq!(metrics.snapshot()["uploadTotal"], pending_payload.len());

        let flushed = time::timeout(
            Duration::from_secs(1),
            read_encrypted_chunk_from_async_stream(&mut upstream, &mut decoder),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(flushed, pending_payload);
    }
}
