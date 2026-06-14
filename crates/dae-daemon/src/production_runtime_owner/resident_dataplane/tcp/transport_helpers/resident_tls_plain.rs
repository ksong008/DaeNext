use super::*;

pub(in crate::production_runtime_owner::resident_dataplane::tcp) const TLS_PLAIN_RELAY_FLUSH_BYTES: usize =
    128 * 1024;
pub(in crate::production_runtime_owner::resident_dataplane::tcp) const TLS_PLAIN_RELAY_FLUSH_DELAY: Duration =
    Duration::from_millis(1);

pub(crate) async fn relay_tcp_over_resident_tls_plain_async(
    inbound: &mut TokioTcpStream,
    client: &mut AsyncResidentTlsClient,
    stop: Arc<AtomicBool>,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut stats = DirectTcpRelayStats::default();
    let mut inbound_closed = false;
    let mut proxy_closed = false;
    let mut last_activity = Instant::now();
    let mut pending_client_flush_bytes = 0_usize;
    let mut pending_client_flush_deadline = None;
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut proxy_buf = [0_u8; 16 * 1024];

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            read = inbound.read(&mut inbound_buf), if !inbound_closed && !proxy_closed => {
                match read {
                    Ok(0) => {
                        flush_pending_tls_plain(
                            client,
                            &mut pending_client_flush_bytes,
                            &mut pending_client_flush_deadline,
                        )
                        .await?;
                        inbound_closed = true;
                        client.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        client
                            .write_plain_all_buffered(&inbound_buf[..read], "write client payload to proxy TLS")
                            .await?;
                        note_pending_tls_plain_flush(
                            &mut pending_client_flush_bytes,
                            &mut pending_client_flush_deadline,
                            read,
                        );
                        if pending_client_flush_bytes >= TLS_PLAIN_RELAY_FLUSH_BYTES {
                            flush_pending_tls_plain(
                                client,
                                &mut pending_client_flush_bytes,
                                &mut pending_client_flush_deadline,
                            )
                            .await?;
                        }
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        flush_pending_tls_plain(
                            client,
                            &mut pending_client_flush_bytes,
                            &mut pending_client_flush_deadline,
                        )
                        .await?;
                        inbound_closed = true;
                        client.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read inbound TCP for proxy TLS relay: {err}")),
                }
            }
            read = client.read_plain(&mut proxy_buf), if !proxy_closed => {
                match read {
                    Ok(0) => {
                        proxy_closed = true;
                        let _ = inbound.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        if let Err(err) = inbound.write_all(&proxy_buf[..read]).await {
                            if is_graceful_stream_close_error(&err) {
                                break;
                            }
                            return Err(format!("write proxy TLS payload to client: {err}"));
                        }
                        stats.direct_to_client += read;
                        metrics.add_download(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_tls_plain_close_error(&err) => {
                        proxy_closed = true;
                        let _ = inbound.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read proxy TLS plaintext: {err}")),
                }
            }
            _ = time::sleep_until(tls_plain_flush_deadline(pending_client_flush_deadline)), if pending_client_flush_deadline.is_some() => {
                flush_pending_tls_plain(
                    client,
                    &mut pending_client_flush_bytes,
                    &mut pending_client_flush_deadline,
                )
                .await?;
                last_activity = Instant::now();
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident proxy TLS relay idle timeout".to_owned());
                }
            }
        }

        if proxy_closed || (inbound_closed && proxy_closed) {
            break;
        }
    }
    Ok(stats)
}

pub(in crate::production_runtime_owner::resident_dataplane::tcp) async fn flush_pending_tls_plain(
    client: &mut AsyncResidentTlsClient,
    pending_client_flush_bytes: &mut usize,
    pending_client_flush_deadline: &mut Option<Instant>,
) -> Result<(), String> {
    if *pending_client_flush_bytes == 0 {
        *pending_client_flush_deadline = None;
        return Ok(());
    }
    client
        .flush_plain("write client payload to proxy TLS")
        .await?;
    *pending_client_flush_bytes = 0;
    *pending_client_flush_deadline = None;
    Ok(())
}

pub(in crate::production_runtime_owner::resident_dataplane::tcp) fn note_pending_tls_plain_flush(
    pending_client_flush_bytes: &mut usize,
    pending_client_flush_deadline: &mut Option<Instant>,
    written: usize,
) {
    if written == 0 {
        return;
    }
    if *pending_client_flush_bytes == 0 {
        *pending_client_flush_deadline = Some(Instant::now() + TLS_PLAIN_RELAY_FLUSH_DELAY);
    }
    *pending_client_flush_bytes += written;
}

pub(in crate::production_runtime_owner::resident_dataplane::tcp) fn tls_plain_flush_deadline(
    deadline: Option<Instant>,
) -> time::Instant {
    time::Instant::from_std(deadline.unwrap_or_else(Instant::now))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_plain_relay_uses_coalesced_flush_threshold() {
        assert!(TLS_PLAIN_RELAY_FLUSH_BYTES >= 64 * 1024);
        assert!(TLS_PLAIN_RELAY_FLUSH_DELAY <= Duration::from_millis(5));
    }

    #[test]
    fn tls_plain_flush_deadline_is_not_reset_by_later_pending_writes() {
        let mut pending = 0_usize;
        let mut deadline = None;
        note_pending_tls_plain_flush(&mut pending, &mut deadline, 1);
        let first = deadline;
        note_pending_tls_plain_flush(&mut pending, &mut deadline, 2);

        assert_eq!(pending, 3);
        assert_eq!(deadline, first);
    }
}
