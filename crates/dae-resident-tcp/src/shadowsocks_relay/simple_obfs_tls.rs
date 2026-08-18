use super::*;
#[allow(clippy::too_many_arguments)]
pub async fn relay_tcp_over_shadowsocks_simple_obfs_tls_async(
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
) -> Result<DirectTcpRelayStats, String> {
    let target_metadata = ShadowsocksMetadata::parse(target)
        .map_err(|err| format!("parse Shadowsocks simple-obfs TLS target: {err}"))?;
    let mut first_plain = target_metadata
        .encode()
        .map_err(|err| format!("encode Shadowsocks simple-obfs TLS target metadata: {err}"))?;
    first_plain.extend_from_slice(&initial_payload);
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
    // Bound the whole TLS handshake stage (request write + response read) so a
    // peer that never answers cannot hold the flow permit for longer than the
    // shared connect timeout used by the other resident handshake paths.
    let response_payload = time::timeout(RESIDENT_CONNECT_TIMEOUT, async {
        proxy
            .write_all(&obfs_request)
            .await
            .map_err(|err| format!("write Shadowsocks simple-obfs TLS request: {err}"))?;
        read_simple_obfs_tls_response_payload_from_async_stream(proxy)
            .await
            .map_err(|err| format!("read Shadowsocks simple-obfs TLS response: {err}"))
    })
    .await
    .map_err(|_| "Shadowsocks simple-obfs TLS handshake timeout".to_owned())??;

    let mut stats = DirectTcpRelayStats::default();
    if !initial_payload.is_empty() {
        stats.client_to_direct += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }
    drop((
        first_plain,
        encrypted_initial,
        obfs_request,
        initial_payload,
    ));

    let (mut proxy_read, mut proxy_write) = proxy.split();
    let mut proxy_reader = AsyncSimpleObfsTlsAppDataReader::new(response_payload, &mut proxy_read);
    let mut server_salt = vec![0_u8; salt_len];
    proxy_reader
        .read_exact(&mut server_salt)
        .await
        .map_err(|err| format!("read Shadowsocks simple-obfs TLS server salt: {err}"))?;
    let mut decoder = AeadStreamCodec::new(cipher, password, &server_salt)
        .map_err(|err| format!("create Shadowsocks simple-obfs TLS response decoder: {err}"))?;
    let (progress, activity) = resident_duplex_progress();
    if stats.client_to_direct != 0 {
        progress.record_upload(stats.client_to_direct);
    }
    let (inbound_read, inbound_write) = tokio::io::split(&mut *inbound);
    let mut inbound_buf = Box::new([0_u8; SHADOWSOCKS_AEAD_TCP_UPLOAD_BUFFER_SIZE]);
    let upload_progress = progress.clone();
    let upload = async move {
        let mut inbound_read = inbound_read;
        loop {
            let read = match inbound_read
                .read(encoder.chunk_payload_buffer(inbound_buf.as_mut()))
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
                    return Err(format!(
                        "read inbound TCP for Shadowsocks simple-obfs TLS upload: {err}"
                    ));
                }
            };
            let wire_len = encoder
                .encrypt_chunk_in_place(inbound_buf.as_mut(), read)
                .map_err(|err| {
                    format!("encrypt Shadowsocks simple-obfs TLS upload chunk: {err}")
                })?;
            let header = simple_obfs_tls_application_data_header(wire_len)?;
            write_all_vectored_header_payload(&mut proxy_write, &header, &inbound_buf[..wire_len])
                .await
                .map_err(|err| format!("write Shadowsocks simple-obfs TLS upload chunk: {err}"))?;
            upload_progress.record_upload(read);
            metrics.add_upload(read);
        }
    };
    let download_progress = progress.clone();
    let download = async move {
        let mut inbound_write = inbound_write;
        let mut buffer = Box::new([0_u8; SHADOWSOCKS_AEAD_TCP_DOWNLOAD_BUFFER_SIZE]);
        loop {
            match read_encrypted_chunk_in_place_from_async_stream(
                &mut proxy_reader,
                &mut decoder,
                buffer.as_mut(),
            )
            .await
            {
                Ok(plain_len) => {
                    if plain_len != 0 {
                        inbound_write
                            .write_all(&buffer[..plain_len])
                            .await
                            .map_err(|err| {
                                format!("write Shadowsocks simple-obfs TLS response: {err}")
                            })?;
                        metrics.add_download(plain_len);
                    }
                    download_progress.record_download(plain_len);
                }
                Err(err) => {
                    let message = err.to_string();
                    if is_graceful_shadowsocks_response_message(&message) {
                        let _ = inbound_write.shutdown().await;
                        return Ok(());
                    }
                    return Err(format!(
                        "read Shadowsocks simple-obfs TLS response: {message}"
                    ));
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
        "resident Shadowsocks simple-obfs TLS relay idle timeout",
        Some(RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT),
    )
    .await
}
