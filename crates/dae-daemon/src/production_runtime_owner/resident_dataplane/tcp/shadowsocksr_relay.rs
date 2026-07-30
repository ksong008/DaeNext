use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_shadowsocksr_http_simple_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    cipher: &str,
    password: &str,
    obfs_host: &str,
    obfs_port: u16,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream_async(&selection).await?;
    let mut client_iv = [0_u8; 16];
    fastrand::fill(&mut client_iv);
    let initial_payload = sniff.take_payload();
    let initial_payload_len = initial_payload.len();
    let (request, mut encoder) = shadowsocksr_http_simple_origin_request(
        cipher,
        password,
        &selection.route.dial_target,
        &initial_payload,
        obfs_host,
        obfs_port,
        client_iv,
    )
    .map_err(|err| format!("build ShadowsocksR stream request: {err}"))?;
    proxy
        .write_all(&request)
        .await
        .map_err(|err| format!("write ShadowsocksR stream request: {err}"))?;
    proxy
        .flush()
        .await
        .map_err(|err| format!("flush ShadowsocksR stream request: {err}"))?;
    metrics.add_upload(initial_payload_len);
    drop((request, initial_payload));

    let (response_head, leftover) = read_http_head_and_leftover_from_async_stream(&mut proxy)
        .await
        .map_err(|err| format!("read ShadowsocksR obfs response: {err}"))?;
    validate_simple_obfs_http_response_status(&response_head)
        .map_err(|err| format!("validate ShadowsocksR obfs response: {err}"))?;
    let mut decoder = ShadowsocksRStreamDecoder::new(cipher, password)
        .map_err(|err| format!("create ShadowsocksR stream decoder: {err}"))?;
    if !leftover.is_empty() {
        let decoded = decoder
            .decode(&leftover)
            .map_err(|err| format!("decode ShadowsocksR initial response payload: {err}"))?;
        if !decoded.is_empty() {
            inbound
                .write_all(&decoded)
                .await
                .map_err(|err| format!("write ShadowsocksR initial response to client: {err}"))?;
            metrics.add_download(decoded.len());
        }
    }
    drop((response_head, leftover));

    relay_tcp_shadowsocksr_stream_async(
        inbound,
        &mut proxy,
        stop,
        metrics,
        &mut encoder,
        &mut decoder,
    )
    .await
    .map(|mut stats| {
        stats.client_to_direct += initial_payload_len;
        generic_proxy_tcp_finished_event(
            peer,
            original_dst,
            &selection,
            sniff,
            "shadowsocksr",
            &stats,
            "plain-tcp-relay",
        )
    })
    .or_else(|err| {
        Ok::<Value, String>(generic_proxy_tcp_failed_event(
            peer,
            original_dst,
            &selection,
            sniff,
            "shadowsocksr",
            &err,
            "plain-tcp-relay",
        ))
    })
}

pub(crate) async fn relay_tcp_shadowsocksr_stream_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    proxy: &mut TokioTcpStream,
    stop: SharedResidentStopSignal,
    metrics: &ResidentDataplaneMetrics,
    encoder: &mut ShadowsocksRStreamEncoder,
    decoder: &mut ShadowsocksRStreamDecoder,
) -> Result<DirectTcpRelayStats, String> {
    let (progress, activity) = resident_duplex_progress();
    let (inbound_read, inbound_write) = tokio::io::split(&mut *inbound);
    let (proxy_read, proxy_write) = proxy.split();
    let upload_progress = progress.clone();
    let upload = async move {
        let mut inbound_read = inbound_read;
        let mut proxy_write = proxy_write;
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = match inbound_read.read(&mut buffer).await {
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
                    return Err(format!("read inbound TCP for ShadowsocksR relay: {err}"));
                }
            };
            let encoded = encoder
                .encode(&buffer[..read])
                .map_err(|err| format!("encode ShadowsocksR upload payload: {err}"))?;
            proxy_write
                .write_all(&encoded)
                .await
                .map_err(|err| format!("write ShadowsocksR upload payload: {err}"))?;
            upload_progress.record_upload(read);
            metrics.add_upload(read);
        }
    };
    let download_progress = progress.clone();
    let download = async move {
        let mut inbound_write = inbound_write;
        let mut proxy_read = proxy_read;
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = match proxy_read.read(&mut buffer).await {
                Ok(0) => {
                    let _ = inbound_write.shutdown().await;
                    return Ok(());
                }
                Ok(read) => read,
                Err(err) if is_graceful_stream_close_error(&err) => {
                    let _ = inbound_write.shutdown().await;
                    return Ok(());
                }
                Err(err) => return Err(format!("read ShadowsocksR proxy TCP: {err}")),
            };
            let decoded = decoder
                .decode(&buffer[..read])
                .map_err(|err| format!("decode ShadowsocksR download payload: {err}"))?;
            if decoded.is_empty() {
                continue;
            }
            match inbound_write.write_all(&decoded).await {
                Ok(()) => {}
                Err(err) if is_graceful_stream_close_error(&err) => return Ok(()),
                Err(err) => {
                    return Err(format!(
                        "write ShadowsocksR download payload to client: {err}"
                    ));
                }
            }
            download_progress.record_download(decoded.len());
            metrics.add_download(decoded.len());
        }
    };
    run_resident_duplex_relay(
        Box::pin(upload),
        Box::pin(download),
        stop,
        &progress,
        activity,
        "resident ShadowsocksR relay idle timeout",
        None,
    )
    .await
}
