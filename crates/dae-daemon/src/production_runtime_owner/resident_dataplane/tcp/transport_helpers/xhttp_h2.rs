use super::*;
pub(crate) async fn open_xhttp_h2_packet_up_session(
    client: AsyncResidentTlsClient,
    proxy: &ResidentProxyPlan,
    session_id: &str,
) -> Result<
    (
        h2::client::SendRequest<Bytes>,
        h2::RecvStream,
        tokio::task::JoinHandle<()>,
    ),
    String,
> {
    let (mut sender, connection) =
        time::timeout(RESIDENT_CONNECT_TIMEOUT, h2::client::handshake(client))
            .await
            .map_err(|_| "xHTTP HTTP/2 handshake timeout".to_owned())?
            .map_err(|err| format!("xHTTP HTTP/2 client handshake: {err}"))?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = xhttp_h2_request(
        http::Method::GET,
        proxy,
        &xhttp_session_path_suffix(session_id, None),
        false,
    )?;
    let (response, _send_stream) = sender
        .send_request(request, true)
        .map_err(|err| format!("send xHTTP HTTP/2 download request headers: {err}"))?;
    let response = time::timeout(RESIDENT_CONNECT_TIMEOUT, response)
        .await
        .map_err(|_| "xHTTP HTTP/2 download response headers timeout".to_owned())?
        .map_err(|err| format!("read xHTTP HTTP/2 download response headers: {err}"))?;
    if !response.status().is_success() {
        connection_task.abort();
        return Err(format!(
            "xHTTP HTTP/2 download response status {}",
            response.status()
        ));
    }
    Ok((sender, response.into_body(), connection_task))
}

pub(crate) async fn send_xhttp_h2_packet_up_request(
    sender: &mut h2::client::SendRequest<Bytes>,
    proxy: &ResidentProxyPlan,
    session_id: &str,
    seq: u64,
    payload: Bytes,
) -> Result<(), String> {
    let request = xhttp_h2_request(
        http::Method::POST,
        proxy,
        &xhttp_session_path_suffix(session_id, Some(seq)),
        true,
    )?;
    let (response, mut send_stream) = sender
        .send_request(request, false)
        .map_err(|err| format!("send xHTTP HTTP/2 packet-up request headers: {err}"))?;
    send_h2_data_with_context(&mut send_stream, payload, true, "xHTTP HTTP/2 packet-up").await?;
    let response = time::timeout(RESIDENT_CONNECT_TIMEOUT, response)
        .await
        .map_err(|_| "xHTTP HTTP/2 packet-up response headers timeout".to_owned())?
        .map_err(|err| format!("read xHTTP HTTP/2 packet-up response headers: {err}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "xHTTP HTTP/2 packet-up response status {}",
            response.status()
        ));
    }
    drain_xhttp_h2_response_body(response.into_body()).await
}

pub(crate) fn xhttp_h2_request(
    method: http::Method,
    proxy: &ResidentProxyPlan,
    path_suffix: &str,
    has_body: bool,
) -> Result<http::Request<()>, String> {
    let uri = xhttp_uri(proxy, path_suffix);
    let referer = xhttp_padding_referer(&xhttp_uri(proxy, ""));
    let mut builder = http::Request::builder()
        .method(method)
        .uri(uri)
        .header(http::header::USER_AGENT, "Mozilla/5.0")
        .header(http::header::ACCEPT, "*/*")
        .header(http::header::ACCEPT_LANGUAGE, "en-US,en;q=0.9")
        .header(http::header::CACHE_CONTROL, "no-cache")
        .header("pragma", "no-cache")
        .header(http::header::REFERER, referer);
    if has_body {
        builder = builder.header(http::header::CONTENT_TYPE, "application/grpc");
    }
    builder
        .body(())
        .map_err(|err| format!("build xHTTP HTTP/2 request: {err}"))
}

pub(crate) fn xhttp_uri(proxy: &ResidentProxyPlan, path_suffix: &str) -> String {
    let normalized = ir::normalize_xhttp_path_and_query(&proxy.stream_path);
    let mut path = normalized.path;
    path.push_str(path_suffix);
    let mut uri = format!("https://{}{}", xhttp_authority(proxy), path);
    if !normalized.query.is_empty() {
        uri.push('?');
        uri.push_str(&normalized.query);
    }
    uri
}

pub(crate) fn xhttp_padding_referer(base_uri: &str) -> String {
    const DEFAULT_PADDING_LEN: usize = 128;
    let base_without_query = base_uri.split_once('?').map_or(base_uri, |(base, _)| base);
    format!(
        "{base_without_query}?x_padding={}",
        "X".repeat(DEFAULT_PADDING_LEN)
    )
}

pub(crate) fn xhttp_authority(proxy: &ResidentProxyPlan) -> String {
    if proxy.stream_host.is_empty() {
        proxy.server_name.clone()
    } else {
        proxy.stream_host.clone()
    }
}

pub(crate) fn xhttp_session_path_suffix(session_id: &str, seq: Option<u64>) -> String {
    match seq {
        Some(seq) => format!("{session_id}/{seq}"),
        None => session_id.to_owned(),
    }
}

pub(crate) fn new_xhttp_session_id() -> String {
    let high = fastrand::u64(..);
    let low = fastrand::u64(..);
    let value = ((high as u128) << 64) | low as u128;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (value >> 96) as u32,
        ((value >> 80) & 0xffff) as u16,
        ((value >> 64) & 0xffff) as u16,
        ((value >> 48) & 0xffff) as u16,
        value & 0xffff_ffff_ffff
    )
}

pub(crate) async fn drain_xhttp_h2_response_body(mut body: h2::RecvStream) -> Result<(), String> {
    loop {
        let data = time::timeout(RESIDENT_CONNECT_TIMEOUT, body.data())
            .await
            .map_err(|_| "xHTTP HTTP/2 packet-up response body timeout".to_owned())?;
        let Some(data) = data else {
            return Ok(());
        };
        let bytes =
            data.map_err(|err| format!("read xHTTP HTTP/2 packet-up response body: {err}"))?;
        body.flow_control()
            .release_capacity(bytes.len())
            .map_err(|err| format!("release xHTTP HTTP/2 packet-up response capacity: {err}"))?;
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp_over_xhttp_h2_packet_up(
    inbound: &mut TokioTcpStream,
    sender: &mut h2::client::SendRequest<Bytes>,
    recv_stream: &mut h2::RecvStream,
    proxy: &ResidentProxyPlan,
    session_id: &str,
    mut seq: u64,
    stop: Arc<AtomicBool>,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut inbound_closed = false;
    let mut response_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut response_stripper = VlessResponseStripper::default();

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        send_xhttp_h2_packet_up_request(
                            sender,
                            proxy,
                            session_id,
                            seq,
                            Bytes::copy_from_slice(&inbound_buf[..read]),
                        )
                        .await?;
                        seq = seq.saturating_add(1);
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read inbound TCP for xHTTP relay: {err}")),
                }
            }
            data = recv_stream.data(), if !response_closed => {
                match data {
                    Some(Ok(bytes)) => {
                        recv_stream
                            .flow_control()
                            .release_capacity(bytes.len())
                            .map_err(|err| format!("release xHTTP HTTP/2 download capacity: {err}"))?;
                        let payload = response_stripper.consume(&bytes)?;
                        if !payload.is_empty() {
                            inbound
                                .write_all(&payload)
                                .await
                                .map_err(|err| format!("write xHTTP response to inbound: {err}"))?;
                            stats.direct_to_client += payload.len();
                            metrics.add_download(payload.len());
                        }
                        last_activity = Instant::now();
                    }
                    Some(Err(err)) => return Err(format!("read xHTTP HTTP/2 download data: {err}")),
                    None => {
                        response_closed = true;
                        let _ = inbound.shutdown().await;
                        last_activity = Instant::now();
                    }
                }
            }
            _ = time::sleep(RESIDENT_IDLE_SLEEP) => {
                if response_closed || (inbound_closed && response_closed) {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident xHTTP HTTP/2 relay idle timeout".to_owned());
                }
            }
        }
    }
    Ok(stats)
}
