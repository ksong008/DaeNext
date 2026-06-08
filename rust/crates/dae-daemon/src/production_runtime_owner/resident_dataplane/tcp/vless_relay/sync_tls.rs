use super::*;
pub(crate) fn relay_tcp_over_vless_tls(
    inbound: &mut TcpStream,
    client: &mut VlessTlsClient,
    stop: &AtomicBool,
    flow: &str,
    user_uuid: [u8; 16],
    initial_payload: &[u8],
    metrics: &ResidentDataplaneMetrics,
) -> Result<RelayStats, RelayError> {
    let mut stats = RelayStats::default();
    let mut stripper = VlessResponseStripper::default();
    let vision_enabled = flow == XTLS_RPRX_VISION;
    let mut vision = vision_enabled.then(|| VisionUnpadder::new(user_uuid));
    let mut downlink_direct = false;
    let mut vision_uplink_mode = VisionUplinkMode::Padding;
    let mut vision_tls_state = VisionInnerTlsState::new();
    let mut uplink_uuid_sent = false;
    let mut vision_first_uplink_block = true;
    let mut pending_vision_uplink = Vec::<u8>::new();
    let mut inbound_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut proxy_buf = [0_u8; 16 * 1024];
    if !initial_payload.is_empty() {
        if vision_enabled {
            pending_vision_uplink.extend_from_slice(initial_payload);
            drain_vision_uplink(
                &mut pending_vision_uplink,
                client,
                stop,
                user_uuid,
                &mut uplink_uuid_sent,
                &mut vision_first_uplink_block,
                &mut vision_uplink_mode,
                &mut vision_tls_state,
            )
            .map_err(|err| RelayError::new(err, &stats))?;
        } else {
            client
                .queue_plain(initial_payload, "queue sniffed client payload to proxy TLS")
                .map_err(|err| RelayError::new(err.to_string(), &stats))?;
        }
        stats.client_to_proxy += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }
    while !stop.load(Ordering::Relaxed) {
        let mut progressed = false;
        if !inbound_closed {
            match inbound.read(&mut inbound_buf) {
                Ok(0) => {
                    inbound_closed = true;
                    client.send_close_notify();
                    progressed = true;
                }
                Ok(read) => {
                    if vision_enabled {
                        pending_vision_uplink.extend_from_slice(&inbound_buf[..read]);
                        if pending_vision_uplink.len() > TLS_RECORD_MAX_PAYLOAD_LEN * 4 {
                            return Err(RelayError::new(
                                format!(
                                    "pending Vision uplink payload did not form complete TLS records: {} bytes",
                                    pending_vision_uplink.len()
                                ),
                                &stats,
                            ));
                        }
                        drain_vision_uplink(
                            &mut pending_vision_uplink,
                            client,
                            stop,
                            user_uuid,
                            &mut uplink_uuid_sent,
                            &mut vision_first_uplink_block,
                            &mut vision_uplink_mode,
                            &mut vision_tls_state,
                        )
                        .map_err(|err| RelayError::new(err, &stats))?;
                    } else {
                        client
                            .queue_plain(&inbound_buf[..read], "queue client payload to proxy TLS")
                            .map_err(|err| RelayError::new(err.to_string(), &stats))?;
                    }
                    stats.client_to_proxy += read;
                    metrics.add_upload(read);
                    progressed = true;
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) => {}
                Err(err) if is_graceful_stream_close_error(&err) => {
                    inbound_closed = true;
                    client.send_close_notify();
                    progressed = true;
                }
                Err(err) => {
                    return Err(RelayError::new(format!("read inbound TCP: {err}"), &stats));
                }
            }
        }

        if downlink_direct {
            match client.raw_read(&mut proxy_buf) {
                Ok(0) => {
                    break;
                }
                Ok(read) => {
                    match write_all_nonblocking(
                        inbound,
                        &proxy_buf[..read],
                        stop,
                        "write VLESS Vision direct payload to client",
                    ) {
                        Ok(()) => {}
                        Err(err) if is_graceful_stream_close_message(&err) => break,
                        Err(err) => return Err(RelayError::new(err, &stats)),
                    }
                    stats.proxy_to_client += read;
                    metrics.add_download(read);
                    progressed = true;
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) => {}
                Err(err) => {
                    return Err(RelayError::new(
                        format!("read VLESS Vision direct TCP: {err}"),
                        &stats,
                    ));
                }
            }
        } else {
            match drive_tls_io_record_aware(client)
                .map_err(|err| RelayError::new(err.to_string(), &stats))?
            {
                TlsDriveOutcome::Progressed(tls_progressed) => progressed |= tls_progressed,
                TlsDriveOutcome::DecryptErrorRawRecord { record, error } => {
                    if can_recover_vision_raw_direct_after_tls_error(
                        vision_enabled,
                        stats.response_header_stripped,
                        vision.as_ref(),
                    ) {
                        downlink_direct = true;
                        stats.vision_downlink_direct_active = true;
                        stats.vision_raw_direct_recovered = true;
                        write_all_nonblocking(
                            inbound,
                            &record,
                            stop,
                            "write recovered VLESS Vision raw-direct payload to client",
                        )
                        .map_err(|err| RelayError::new(err, &stats))?;
                        stats.proxy_to_client += record.len();
                        metrics.add_download(record.len());
                        progressed = true;
                    } else {
                        return Err(RelayError::new(error, &stats));
                    }
                }
            }
            loop {
                match client.read_plain(&mut proxy_buf) {
                    Ok(0) => break,
                    Ok(read) => {
                        let mut payload = stripper
                            .consume(&proxy_buf[..read])
                            .map_err(|err| RelayError::new(err, &stats))?;
                        stats.response_header_stripped = stripper.done;
                        if let Some(vision) = vision.as_mut()
                            && !payload.is_empty()
                        {
                            payload = vision
                                .consume(&payload)
                                .map_err(|err| RelayError::new(err, &stats))?;
                            vision_tls_state
                                .observe_server_payload(&payload)
                                .map_err(|err| RelayError::new(err, &stats))?;
                            stats.vision_unpadding_blocks = vision.completed_blocks;
                            stats.vision_direct_command_seen = vision.direct_command_seen;
                            downlink_direct = vision.direct_command_seen;
                            stats.vision_downlink_direct_active = downlink_direct;
                            if !pending_vision_uplink.is_empty() {
                                drain_vision_uplink(
                                    &mut pending_vision_uplink,
                                    client,
                                    stop,
                                    user_uuid,
                                    &mut uplink_uuid_sent,
                                    &mut vision_first_uplink_block,
                                    &mut vision_uplink_mode,
                                    &mut vision_tls_state,
                                )
                                .map_err(|err| RelayError::new(err, &stats))?;
                            }
                        }
                        if !payload.is_empty() {
                            write_all_nonblocking(
                                inbound,
                                &payload,
                                stop,
                                "write VLESS payload to client",
                            )
                            .map_err(|err| RelayError::new(err, &stats))?;
                            stats.proxy_to_client += payload.len();
                            metrics.add_download(payload.len());
                        }
                        progressed = true;
                        if downlink_direct {
                            break;
                        }
                    }
                    Err(err)
                        if matches!(
                            err.kind(),
                            ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                        ) =>
                    {
                        break;
                    }
                    Err(err) => {
                        return Err(RelayError::new(
                            format!("read VLESS TLS plaintext: {err}"),
                            &stats,
                        ));
                    }
                }
            }
        }

        if inbound_closed && !downlink_direct && client.idle_tls_complete() {
            break;
        }
        if progressed {
            last_activity = Instant::now();
        } else if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
            return Err(RelayError::new("resident TCP relay idle timeout", &stats));
        } else {
            thread::sleep(RESIDENT_IDLE_SLEEP);
        }
    }
    Ok(stats)
}
