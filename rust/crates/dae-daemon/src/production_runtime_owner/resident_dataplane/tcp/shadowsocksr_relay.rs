use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_shadowsocksr_http_simple_proxy_tcp_connection(
    inbound: &mut TcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpProxySelection,
    stop: &AtomicBool,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    cipher: &str,
    password: &str,
    obfs_host: &str,
    obfs_port: u16,
) -> Result<Value, String> {
    let mut proxy = open_plain_proxy_tcp_stream(&selection.proxy)?;
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
    .map_err(|err| format!("build ShadowsocksR legacy stream request: {err}"))?;
    proxy
        .write_all(&request)
        .map_err(|err| format!("write ShadowsocksR legacy stream request: {err}"))?;
    proxy
        .flush()
        .map_err(|err| format!("flush ShadowsocksR legacy stream request: {err}"))?;
    metrics.add_upload(sniff.payload.len());

    let (response_head, leftover) = read_http_head_and_leftover_from_stream(&mut proxy)
        .map_err(|err| format!("read ShadowsocksR legacy obfs response: {err}"))?;
    validate_simple_obfs_http_response_status(&response_head)
        .map_err(|err| format!("validate ShadowsocksR legacy obfs response: {err}"))?;
    let mut decoder = ShadowsocksRStreamDecoder::new(cipher, password)
        .map_err(|err| format!("create ShadowsocksR stream decoder: {err}"))?;
    if !leftover.is_empty() {
        let decoded = decoder
            .decode(&leftover)
            .map_err(|err| format!("decode ShadowsocksR initial response payload: {err}"))?;
        if !decoded.is_empty() {
            inbound
                .write_all(&decoded)
                .map_err(|err| format!("write ShadowsocksR initial response to client: {err}"))?;
            metrics.add_download(decoded.len());
        }
    }

    proxy
        .set_nonblocking(true)
        .map_err(|err| format!("set ShadowsocksR proxy TCP nonblocking: {err}"))?;
    inbound.set_nonblocking(true).map_err(|err| {
        format!("set inbound TCP nonblocking after ShadowsocksR handshake: {err}")
    })?;
    relay_tcp_shadowsocksr_stream(
        inbound,
        &mut proxy,
        stop,
        metrics,
        &mut encoder,
        &mut decoder,
    )
    .map(|mut stats| {
        stats.client_to_direct += sniff.payload.len();
        generic_proxy_tcp_finished_event(
            peer,
            original_dst,
            selection,
            sniff,
            "shadowsocksr",
            &stats,
            "legacy-stream-relay",
        )
    })
    .or_else(|err| {
        Ok::<Value, String>(generic_proxy_tcp_failed_event(
            peer,
            original_dst,
            selection,
            sniff,
            "shadowsocksr",
            &err,
            "legacy-stream-relay",
        ))
    })
}

fn relay_tcp_shadowsocksr_stream(
    inbound: &mut TcpStream,
    proxy: &mut TcpStream,
    stop: &AtomicBool,
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
        let mut progressed = false;
        if !inbound_closed && !proxy_closed {
            match inbound.read(&mut inbound_buf) {
                Ok(0) => {
                    inbound_closed = true;
                    let _ = proxy.shutdown(Shutdown::Write);
                    progressed = true;
                }
                Ok(read) => {
                    let encoded = encoder
                        .encode(&inbound_buf[..read])
                        .map_err(|err| format!("encode ShadowsocksR upload payload: {err}"))?;
                    write_all_nonblocking(
                        proxy,
                        &encoded,
                        stop,
                        "write ShadowsocksR upload payload",
                    )?;
                    stats.client_to_direct += read;
                    metrics.add_upload(read);
                    progressed = true;
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) => {}
                Err(err) => return Err(format!("read inbound TCP for ShadowsocksR relay: {err}")),
            }
        }

        if !proxy_closed {
            match proxy.read(&mut proxy_buf) {
                Ok(0) => {
                    proxy_closed = true;
                    let _ = inbound.shutdown(Shutdown::Write);
                    progressed = true;
                }
                Ok(read) => {
                    let decoded = decoder
                        .decode(&proxy_buf[..read])
                        .map_err(|err| format!("decode ShadowsocksR download payload: {err}"))?;
                    if !decoded.is_empty() {
                        match write_all_nonblocking(
                            inbound,
                            &decoded,
                            stop,
                            "write ShadowsocksR download payload to client",
                        ) {
                            Ok(()) => {}
                            Err(err) if graceful_stream_close_message(&err) => break,
                            Err(err) => return Err(err),
                        }
                        stats.direct_to_client += decoded.len();
                        metrics.add_download(decoded.len());
                    }
                    progressed = true;
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) => {}
                Err(err) => return Err(format!("read ShadowsocksR proxy TCP: {err}")),
            }
        }

        if proxy_closed || (inbound_closed && proxy_closed) {
            break;
        }
        if progressed {
            last_activity = Instant::now();
        } else if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
            return Err("resident ShadowsocksR relay idle timeout".to_owned());
        } else {
            thread::sleep(RESIDENT_IDLE_SLEEP);
        }
    }
    Ok(stats)
}

fn graceful_stream_close_message(message: &str) -> bool {
    message.contains("Broken pipe")
        || message.contains("Connection reset")
        || message.contains("Connection aborted")
        || message.contains("Not connected")
        || message.contains("broken pipe")
        || message.contains("connection reset")
        || message.contains("connection aborted")
        || message.contains("not connected")
}
