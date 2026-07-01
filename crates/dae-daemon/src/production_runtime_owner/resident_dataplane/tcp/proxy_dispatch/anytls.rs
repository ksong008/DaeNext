use super::*;
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_anytls_tls_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    auth: &str,
) -> Result<Value, String> {
    let mut client =
        open_async_resident_tls_client_with_flow(&selection.proxy, selection.mark, selection.mptcp)
            .await?;
    let tls_underlay = async_resident_tls_underlay_name(&client);
    let sid = 1_u32;
    client
        .write_plain_all(
            &anytls_link::handshake_auth_bytes(auth),
            "write AnyTLS auth handshake",
        )
        .await?;
    write_anytls_frame(
        &mut client,
        anytls_contract::CMD_SETTINGS,
        sid,
        &anytls_link::settings_bytes(),
        "write AnyTLS settings",
    )
    .await?;
    write_anytls_frame(
        &mut client,
        anytls_contract::CMD_SYN,
        sid,
        &[],
        "write AnyTLS SYN",
    )
    .await?;
    let target_addr = anytls_link::socks_addr(&selection.route.dial_target)
        .map_err(|err| format!("build AnyTLS target address: {err}"))?;
    write_anytls_frame(
        &mut client,
        anytls_contract::CMD_PSH,
        sid,
        &target_addr,
        "write AnyTLS target",
    )
    .await?;
    if !sniff.payload.is_empty() {
        write_anytls_frame(
            &mut client,
            anytls_contract::CMD_PSH,
            sid,
            &sniff.payload,
            "write AnyTLS initial payload",
        )
        .await?;
        metrics.add_upload(sniff.payload.len());
    }
    wait_anytls_synack(&mut client, sid).await?;

    match relay_tcp_over_anytls_async(inbound, &mut client, stop, sid, metrics).await {
        Ok(mut stats) => {
            stats.client_to_direct += sniff.payload.len();
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "anytls",
                &stats,
                "async-proxy-frame-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-frame-tls",
                "anytls",
                Some(tls_underlay),
                None,
            );
            Ok(event)
        }
        Err(err) => {
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "anytls",
                &err,
                "async-proxy-frame-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-frame-tls",
                "anytls",
                Some(tls_underlay),
                None,
            );
            Ok(event)
        }
    }
}

pub(crate) async fn write_anytls_frame(
    client: &mut AsyncResidentTlsClient,
    cmd: u8,
    sid: u32,
    data: &[u8],
    label: &str,
) -> Result<(), String> {
    let frame = anytls_link::frame(cmd, sid, data);
    client.write_plain_all(&frame, label).await
}

pub(crate) async fn wait_anytls_synack(
    client: &mut AsyncResidentTlsClient,
    sid: u32,
) -> Result<(), String> {
    loop {
        let frame = read_anytls_frame(client).await?;
        match frame.cmd {
            cmd if cmd == anytls_contract::CMD_SYNACK
                && frame.sid == sid
                && frame.data.is_empty() =>
            {
                return Ok(());
            }
            anytls_contract::CMD_WASTE
            | anytls_contract::CMD_SERVER_SETTINGS
            | anytls_contract::CMD_UPDATE_PADDING
            | anytls_contract::CMD_HEART_RESPONSE => {}
            cmd if cmd == anytls_contract::CMD_ALERT => {
                return Err(format!(
                    "AnyTLS alert before SYNACK: {} bytes",
                    frame.data.len()
                ));
            }
            cmd => {
                return Err(format!(
                    "unexpected AnyTLS frame before SYNACK: cmd={cmd} sid={} len={}",
                    frame.sid,
                    frame.data.len()
                ));
            }
        }
    }
}

pub(crate) async fn relay_tcp_over_anytls_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    client: &mut AsyncResidentTlsClient,
    stop: Arc<AtomicBool>,
    sid: u32,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut stats = DirectTcpRelayStats::default();
    let mut inbound_closed = false;
    let mut proxy_closed = false;
    let mut inbound_close_started = None;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            read = inbound.read(&mut inbound_buf), if !inbound_closed && !proxy_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        if inbound_close_started.is_none() {
                            inbound_close_started = Some(Instant::now());
                        }
                        let _ = write_anytls_frame(
                            client,
                            anytls_contract::CMD_FIN,
                            sid,
                            &[],
                            "write AnyTLS FIN",
                        )
                        .await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        write_anytls_frame(
                            client,
                            anytls_contract::CMD_PSH,
                            sid,
                            &inbound_buf[..read],
                            "write client payload to AnyTLS",
                        )
                        .await?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        if inbound_close_started.is_none() {
                            inbound_close_started = Some(Instant::now());
                        }
                        let _ = write_anytls_frame(
                            client,
                            anytls_contract::CMD_FIN,
                            sid,
                            &[],
                            "write AnyTLS FIN after client close",
                        )
                        .await;
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read inbound TCP for AnyTLS relay: {err}")),
                }
            }
            frame = read_anytls_frame(client), if !proxy_closed => {
                let frame = frame?;
                match frame.cmd {
                    cmd if cmd == anytls_contract::CMD_PSH && frame.sid == sid => {
                        if !frame.data.is_empty() {
                            if let Err(err) = inbound.write_all(&frame.data).await {
                                if is_graceful_stream_close_error(&err) {
                                    break;
                                }
                                return Err(format!("write AnyTLS payload to client: {err}"));
                            }
                            stats.direct_to_client += frame.data.len();
                            metrics.add_download(frame.data.len());
                        }
                        last_activity = Instant::now();
                    }
                    cmd if cmd == anytls_contract::CMD_FIN && frame.sid == sid => {
                        proxy_closed = true;
                        let _ = inbound.shutdown().await;
                        last_activity = Instant::now();
                    }
                    anytls_contract::CMD_WASTE
                    | anytls_contract::CMD_SERVER_SETTINGS
                    | anytls_contract::CMD_UPDATE_PADDING
                    | anytls_contract::CMD_HEART_RESPONSE => {
                        last_activity = Instant::now();
                    }
                    cmd if cmd == anytls_contract::CMD_ALERT => {
                        return Err(format!("AnyTLS alert frame: sid={} len={}", frame.sid, frame.data.len()));
                    }
                    cmd => {
                        return Err(format!(
                            "unexpected AnyTLS relay frame: cmd={cmd} sid={} len={}",
                            frame.sid,
                            frame.data.len()
                        ));
                    }
                }
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if inbound_closed && proxy_closed {
                    break;
                }
                if let Some(started) = inbound_close_started
                    && started.elapsed() >= ANYTLS_LOCAL_CLOSE_DRAIN_TIMEOUT
                {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident AnyTLS relay idle timeout".to_owned());
                }
            }
        }

        if proxy_closed {
            break;
        }
    }
    Ok(stats)
}

pub(crate) async fn read_anytls_frame(
    client: &mut AsyncResidentTlsClient,
) -> Result<AnyTlsFrame, String> {
    let mut header = [0_u8; anytls_contract::HEADER_OVERHEAD_SIZE];
    read_resident_tls_plain_exact(client, &mut header, "read AnyTLS frame header").await?;
    let len = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut data = vec![0_u8; len];
    read_resident_tls_plain_exact(client, &mut data, "read AnyTLS frame data").await?;
    Ok(AnyTlsFrame {
        cmd: header[0],
        sid: u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
        data,
    })
}

pub(crate) async fn read_resident_tls_plain_exact(
    client: &mut AsyncResidentTlsClient,
    buf: &mut [u8],
    label: &str,
) -> Result<(), String> {
    let mut offset = 0_usize;
    while offset < buf.len() {
        let read = time::timeout(
            RESIDENT_TCP_IDLE_TIMEOUT,
            client.read_plain(&mut buf[offset..]),
        )
        .await
        .map_err(|_| format!("{label}: timeout"))?
        .map_err(|err| format!("{label}: {err}"))?;
        if read == 0 {
            return Err(format!("{label}: early eof"));
        }
        offset += read;
    }
    Ok(())
}
