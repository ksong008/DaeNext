use super::*;
pub(crate) async fn relay_tcp_over_vless_tls_async(
    inbound: &mut TokioTcpStream,
    client: &mut AsyncVlessTlsClient,
    stop: Arc<AtomicBool>,
    flow: &str,
    user_uuid: [u8; 16],
    initial_payload: &[u8],
    metrics: &ResidentDataplaneMetrics,
) -> Result<RelayStats, RelayError> {
    let mut stats = RelayStats::default();
    let mut stripper = VlessResponseStripper::default();
    let vision_enabled = is_xtls_rprx_vision_flow(flow);
    let mut vision = vision_enabled.then(|| VisionUnpadder::new(user_uuid));
    let mut downlink_direct = false;
    let mut vision_uplink_mode = VisionUplinkMode::Padding;
    let mut vision_tls_state = VisionInnerTlsState::new();
    let mut uplink_uuid_sent = false;
    let mut vision_first_uplink_block = true;
    let mut pending_vision_uplink = Vec::<u8>::new();
    let mut pending_plain_uplink_flush_bytes = 0_usize;
    let mut pending_plain_uplink_flush_deadline = None;
    let mut inbound_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut proxy_buf = [0_u8; 16 * 1024];

    if !initial_payload.is_empty() {
        if vision_enabled {
            pending_vision_uplink.extend_from_slice(initial_payload);
            drain_vision_uplink_async(
                &mut pending_vision_uplink,
                client,
                &stop,
                user_uuid,
                &mut uplink_uuid_sent,
                &mut vision_first_uplink_block,
                &mut vision_uplink_mode,
                &mut vision_tls_state,
            )
            .await
            .map_err(|err| RelayError::new(err, &stats))?;
        } else {
            client
                .write_plain_all(initial_payload, "write sniffed client payload to proxy TLS")
                .await
                .map_err(|err| RelayError::new(err, &stats))?;
        }
        stats.client_to_proxy += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            inbound_read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match inbound_read {
                    Ok(0) => {
                        if !vision_enabled {
                            flush_pending_tls_plain(
                                client,
                                &mut pending_plain_uplink_flush_bytes,
                                &mut pending_plain_uplink_flush_deadline,
                            )
                            .await
                            .map_err(|err| RelayError::new(err, &stats))?;
                        }
                        inbound_closed = true;
                        client.shutdown().await;
                        last_activity = Instant::now();
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
                            drain_vision_uplink_async(
                                &mut pending_vision_uplink,
                                client,
                                &stop,
                                user_uuid,
                                &mut uplink_uuid_sent,
                                &mut vision_first_uplink_block,
                                &mut vision_uplink_mode,
                                &mut vision_tls_state,
                            )
                            .await
                            .map_err(|err| RelayError::new(err, &stats))?;
                        } else {
                            client
                                .write_plain_all_buffered(&inbound_buf[..read], "write client payload to proxy TLS")
                                .await
                                .map_err(|err| RelayError::new(err, &stats))?;
                            note_pending_tls_plain_flush(
                                &mut pending_plain_uplink_flush_bytes,
                                &mut pending_plain_uplink_flush_deadline,
                                read,
                            );
                            if pending_plain_uplink_flush_bytes >= TLS_PLAIN_RELAY_FLUSH_BYTES {
                                flush_pending_tls_plain(
                                    client,
                                    &mut pending_plain_uplink_flush_bytes,
                                    &mut pending_plain_uplink_flush_deadline,
                                )
                                .await
                                .map_err(|err| RelayError::new(err, &stats))?;
                            }
                        }
                        stats.client_to_proxy += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        if !vision_enabled {
                            flush_pending_tls_plain(
                                client,
                                &mut pending_plain_uplink_flush_bytes,
                                &mut pending_plain_uplink_flush_deadline,
                            )
                            .await
                            .map_err(|err| RelayError::new(err, &stats))?;
                        }
                        inbound_closed = true;
                        client.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Err(err) => {
                        return Err(RelayError::new(format!("read inbound TCP: {err}"), &stats));
                    }
                }
            }
            proxy_read = async {
                if downlink_direct {
                    client.raw_read(&mut proxy_buf).await
                } else {
                    client.read_plain(&mut proxy_buf).await
                }
            } => {
                match proxy_read {
                    Ok(0) => break,
                    Ok(read) => {
                        if downlink_direct {
                            if let Err(err) = inbound.write_all(&proxy_buf[..read]).await {
                                if is_graceful_stream_close_error(&err) {
                                    break;
                                }
                                return Err(RelayError::new(
                                    format!("write VLESS Vision direct payload to client: {err}"),
                                    &stats,
                                ));
                            }
                            stats.proxy_to_client += read;
                            metrics.add_download(read);
                            last_activity = Instant::now();
                            continue;
                        }

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
                                drain_vision_uplink_async(
                                    &mut pending_vision_uplink,
                                    client,
                                    &stop,
                                    user_uuid,
                                    &mut uplink_uuid_sent,
                                    &mut vision_first_uplink_block,
                                    &mut vision_uplink_mode,
                                    &mut vision_tls_state,
                                )
                                .await
                                .map_err(|err| RelayError::new(err, &stats))?;
                            }
                        }
                        if !payload.is_empty() {
                            inbound
                                .write_all(&payload)
                                .await
                                .map_err(|err| RelayError::new(format!("write VLESS payload to client: {err}"), &stats))?;
                            stats.proxy_to_client += payload.len();
                            metrics.add_download(payload.len());
                        }
                        last_activity = Instant::now();
                    }
                    Err(err) => {
                        return Err(RelayError::new(format!("read VLESS TLS plaintext: {err}"), &stats));
                    }
                }
            }
            _ = time::sleep_until(tls_plain_flush_deadline(pending_plain_uplink_flush_deadline)), if !vision_enabled && pending_plain_uplink_flush_deadline.is_some() => {
                flush_pending_tls_plain(
                    client,
                    &mut pending_plain_uplink_flush_bytes,
                    &mut pending_plain_uplink_flush_deadline,
                )
                    .await
                    .map_err(|err| RelayError::new(err, &stats))?;
                last_activity = Instant::now();
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if inbound_closed && !downlink_direct {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err(RelayError::new("resident TCP relay idle timeout", &stats));
                }
            }
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vless_plain_tls_relay_reuses_coalesced_flush_policy() {
        assert!(TLS_PLAIN_RELAY_FLUSH_BYTES >= 64 * 1024);
        assert!(TLS_PLAIN_RELAY_FLUSH_DELAY <= Duration::from_millis(5));
    }
}
