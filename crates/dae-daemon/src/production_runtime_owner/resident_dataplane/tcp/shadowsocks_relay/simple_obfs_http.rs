use super::*;
#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp_over_shadowsocks_simple_obfs_http_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
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
    let target_metadata = ShadowsocksMetadata::parse(target)
        .map_err(|err| format!("parse Shadowsocks simple-obfs target: {err}"))?;
    let mut first_plain = target_metadata
        .encode()
        .map_err(|err| format!("encode Shadowsocks simple-obfs target metadata: {err}"))?;
    first_plain.extend_from_slice(&initial_payload);
    let mut client_salt = vec![0_u8; salt_len];
    fastrand::fill(&mut client_salt);
    let mut encoder = AeadStreamCodec::new(cipher, password, &client_salt)
        .map_err(|err| format!("create Shadowsocks simple-obfs upload encoder: {err}"))?;
    let mut encrypted_initial = client_salt.clone();
    encrypted_initial.extend(
        encoder
            .encrypt_chunk(&first_plain)
            .map_err(|err| format!("encode Shadowsocks simple-obfs initial frame: {err}"))?,
    );
    let options = Sip003SimpleObfsHttpOptions::new(host, path);
    let obfs_request = simple_obfs_http_request_with_body(&options, &encrypted_initial);
    proxy
        .write_all(&obfs_request)
        .await
        .map_err(|err| format!("write Shadowsocks simple-obfs request: {err}"))?;
    let (response_head, response_leftover) = read_http_head_and_leftover_from_async_stream(proxy)
        .await
        .map_err(|err| format!("read Shadowsocks simple-obfs response head: {err}"))?;
    validate_simple_obfs_http_response_status(&response_head)
        .map_err(|err| format!("validate Shadowsocks simple-obfs response status: {err}"))?;

    let mut stats = DirectTcpRelayStats::default();
    if !initial_payload.is_empty() {
        stats.client_to_direct += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }
    drop((
        first_plain,
        encrypted_initial,
        obfs_request,
        response_head,
        initial_payload,
    ));

    let (mut proxy_read, mut proxy_write) = proxy.split();
    let mut proxy_reader = AsyncPrefixTcpReader::new(response_leftover, &mut proxy_read);
    let mut server_salt = vec![0_u8; salt_len];
    proxy_reader
        .read_exact(&mut server_salt)
        .await
        .map_err(|err| format!("read Shadowsocks simple-obfs server salt: {err}"))?;
    let mut decoder = AeadStreamCodec::new(cipher, password, &server_salt)
        .map_err(|err| format!("create Shadowsocks simple-obfs response decoder: {err}"))?;
    let (progress, activity) = resident_duplex_progress();
    if stats.client_to_direct != 0 {
        progress.record_upload(stats.client_to_direct);
    }
    let (inbound_read, inbound_write) = tokio::io::split(&mut *inbound);
    let mut inbound_buf = [0_u8; 16 * 1024];
    let upload_progress = progress.clone();
    let upload = async move {
        let mut inbound_read = inbound_read;
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
                    return Err(format!(
                        "read inbound TCP for Shadowsocks simple-obfs upload: {err}"
                    ));
                }
            };
            let encrypted = encoder
                .encrypt_chunk(&inbound_buf[..read])
                .map_err(|err| format!("encrypt Shadowsocks simple-obfs upload chunk: {err}"))?;
            proxy_write
                .write_all(&encrypted)
                .await
                .map_err(|err| format!("write Shadowsocks simple-obfs upload chunk: {err}"))?;
            upload_progress.record_upload(read);
            metrics.add_upload(read);
        }
    };
    let download_progress = progress.clone();
    let download = async move {
        let mut inbound_write = inbound_write;
        loop {
            match read_encrypted_chunk_from_async_stream(&mut proxy_reader, &mut decoder).await {
                Ok(plain) => {
                    if !plain.is_empty() {
                        inbound_write.write_all(&plain).await.map_err(|err| {
                            format!("write Shadowsocks simple-obfs response: {err}")
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
                    return Err(format!("read Shadowsocks simple-obfs response: {message}"));
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
        "resident Shadowsocks simple-obfs relay idle timeout",
        Some(RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT),
    )
    .await
}
