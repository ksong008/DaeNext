use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_shadowsocksr_http_simple_proxy_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    cipher: &str,
    password: &str,
    obfs_host: &str,
    obfs_port: u16,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream_async(&selection).await?;
    let mut client_iv = [0_u8; 16];
    fastrand::fill(&mut client_iv);
    let (request, mut encoder) = shadowsocksr_http_simple_origin_request(
        cipher,
        password,
        &selection.route.dial_target,
        &sniff.payload,
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
    metrics.add_upload(sniff.payload.len());

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
        stats.client_to_direct += sniff.payload.len();
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

async fn relay_tcp_shadowsocksr_stream_async(
    inbound: &mut TokioTcpStream,
    proxy: &mut TokioTcpStream,
    stop: Arc<AtomicBool>,
    metrics: &ResidentDataplaneMetrics,
    encoder: &mut ShadowsocksRStreamEncoder,
    decoder: &mut ShadowsocksRStreamDecoder,
) -> Result<DirectTcpRelayStats, String> {
    let mut stats = DirectTcpRelayStats::default();
    let mut inbound_closed = false;
    let mut proxy_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut proxy_buf = [0_u8; 16 * 1024];

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            inbound_read = inbound.read(&mut inbound_buf), if !inbound_closed && !proxy_closed => {
                match inbound_read {
                    Ok(0) => {
                        inbound_closed = true;
                        let _ = proxy.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        let encoded = encoder
                            .encode(&inbound_buf[..read])
                            .map_err(|err| format!("encode ShadowsocksR upload payload: {err}"))?;
                        proxy
                            .write_all(&encoded)
                            .await
                            .map_err(|err| format!("write ShadowsocksR upload payload: {err}"))?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        let _ = proxy.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read inbound TCP for ShadowsocksR relay: {err}")),
                }
            }
            proxy_read = proxy.read(&mut proxy_buf), if !proxy_closed => {
                match proxy_read {
                    Ok(0) => {
                        proxy_closed = true;
                        let _ = inbound.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        let decoded = decoder
                            .decode(&proxy_buf[..read])
                            .map_err(|err| format!("decode ShadowsocksR download payload: {err}"))?;
                        if !decoded.is_empty() {
                            match inbound.write_all(&decoded).await {
                                Ok(()) => {}
                                Err(err) if is_graceful_stream_close_error(&err) => break,
                                Err(err) => {
                                    return Err(format!(
                                        "write ShadowsocksR download payload to client: {err}"
                                    ));
                                }
                            }
                            stats.direct_to_client += decoded.len();
                            metrics.add_download(decoded.len());
                        }
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        proxy_closed = true;
                        let _ = inbound.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read ShadowsocksR proxy TCP: {err}")),
                }
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if proxy_closed {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident ShadowsocksR relay idle timeout".to_owned());
                }
            }
        }

        if proxy_closed {
            break;
        }
    }
    Ok(stats)
}
