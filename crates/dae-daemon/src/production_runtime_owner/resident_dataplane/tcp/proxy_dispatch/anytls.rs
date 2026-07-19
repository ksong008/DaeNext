use super::*;
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_anytls_tls_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    owner_registry: Option<&AnyTlsOwnerRegistryHandle>,
    owner_deadline: Option<dae_runtime_control::AbsoluteDeadline>,
) -> Result<Value, String> {
    let owner_registry = owner_registry.ok_or_else(|| {
        "AnyTLS generation transport owner is unavailable for TCP execution".to_owned()
    })?;
    let owner_deadline = owner_deadline.unwrap_or_else(|| {
        dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), RESIDENT_CONNECT_TIMEOUT)
    });
    let mut logical = owner_registry
        .acquire(
            Arc::clone(&selection.proxy),
            selection.route.dial_target.clone(),
            owner_deadline,
        )
        .await?;
    let tls_underlay = logical.tls_underlay();
    let sid = logical.sid();
    let physical_instance = logical.physical_instance_id();
    let physical_reused = logical.reused();
    let initial_payload = sniff.take_payload();
    let initial_payload_len = initial_payload.len();
    if initial_payload_len != 0 {
        logical
            .write_all(&initial_payload)
            .await
            .map_err(|error| format!("write AnyTLS initial logical payload: {error}"))?;
        metrics.add_upload(initial_payload_len);
    }
    drop(initial_payload);

    match relay_tcp_over_anytls_async(inbound, &mut logical, stop, metrics).await {
        Ok(mut stats) => {
            stats.client_to_direct += initial_payload_len;
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
            append_anytls_owner_event_fields(&mut event, sid, physical_instance, physical_reused);
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
            append_anytls_owner_event_fields(&mut event, sid, physical_instance, physical_reused);
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

fn append_anytls_owner_event_fields(
    event: &mut Value,
    sid: u32,
    physical_instance: u64,
    physical_reused: bool,
) {
    event["anytlsSid"] = json!(sid);
    event["anytlsPhysicalInstance"] = json!(physical_instance);
    event["anytlsPhysicalReused"] = json!(physical_reused);
    event["anytlsMode"] = json!("bounded-idle-reuse");
}

pub(crate) async fn relay_tcp_over_anytls_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    logical: &mut AnyTlsLogicalStreamLease,
    stop: SharedResidentStopSignal,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut stats = DirectTcpRelayStats::default();
    let mut inbound_closed = false;
    let mut proxy_closed = false;
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut proxy_buf = [0_u8; 16 * 1024];
    let mut stop_listener = stop.listener();
    let idle_deadline = resident_relay_idle_deadline(RESIDENT_TCP_IDLE_TIMEOUT);
    let local_close_drain_deadline = resident_relay_idle_deadline(ANYTLS_LOCAL_CLOSE_DRAIN_TIMEOUT);
    tokio::pin!(idle_deadline);
    tokio::pin!(local_close_drain_deadline);
    let mut local_close_drain_active = false;

    loop {
        tokio::select! {
            _ = stop_listener.cancelled() => break,
            read = inbound.read(&mut inbound_buf), if !inbound_closed && !proxy_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        let _ = logical.shutdown().await;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                        reset_resident_relay_idle_deadline(
                            local_close_drain_deadline.as_mut(),
                            ANYTLS_LOCAL_CLOSE_DRAIN_TIMEOUT,
                        );
                        local_close_drain_active = true;
                    }
                    Ok(read) => {
                        logical.write_all(&inbound_buf[..read]).await.map_err(|error| {
                            format!("write client payload to AnyTLS logical stream: {error}")
                        })?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        let _ = logical.shutdown().await;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                        reset_resident_relay_idle_deadline(
                            local_close_drain_deadline.as_mut(),
                            ANYTLS_LOCAL_CLOSE_DRAIN_TIMEOUT,
                        );
                        local_close_drain_active = true;
                    }
                    Err(err) => return Err(format!("read inbound TCP for AnyTLS relay: {err}")),
                }
            }
            read = logical.read(&mut proxy_buf), if !proxy_closed => {
                match read {
                    Ok(0) => {
                        proxy_closed = true;
                        let _ = inbound.shutdown().await;
                    }
                    Ok(read) => {
                        if let Err(err) = inbound.write_all(&proxy_buf[..read]).await {
                            if is_graceful_stream_close_error(&err) {
                                break;
                            }
                            return Err(format!("write AnyTLS payload to client: {err}"));
                        }
                        stats.direct_to_client += read;
                        metrics.add_download(read);
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        proxy_closed = true;
                        let _ = inbound.shutdown().await;
                    }
                    Err(err) => return Err(format!("read AnyTLS logical response: {err}")),
                }
            }
            _ = &mut local_close_drain_deadline, if local_close_drain_active => break,
            _ = &mut idle_deadline => {
                return Err("resident AnyTLS relay idle timeout".to_owned());
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
