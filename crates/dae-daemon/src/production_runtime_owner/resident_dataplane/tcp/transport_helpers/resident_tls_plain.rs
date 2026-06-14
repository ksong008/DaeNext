use super::*;

const TLS_PLAIN_RELAY_FLUSH_BYTES: usize = 128 * 1024;
const TLS_PLAIN_RELAY_FLUSH_DELAY: Duration = Duration::from_millis(1);

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
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut proxy_buf = [0_u8; 16 * 1024];

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            read = inbound.read(&mut inbound_buf), if !inbound_closed && !proxy_closed => {
                match read {
                    Ok(0) => {
                        flush_pending_tls_plain(client, &mut pending_client_flush_bytes).await?;
                        inbound_closed = true;
                        client.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        client
                            .write_plain_all_buffered(&inbound_buf[..read], "write client payload to proxy TLS")
                            .await?;
                        pending_client_flush_bytes += read;
                        if pending_client_flush_bytes >= TLS_PLAIN_RELAY_FLUSH_BYTES {
                            flush_pending_tls_plain(client, &mut pending_client_flush_bytes).await?;
                        }
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        flush_pending_tls_plain(client, &mut pending_client_flush_bytes).await?;
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
            _ = time::sleep(TLS_PLAIN_RELAY_FLUSH_DELAY), if pending_client_flush_bytes > 0 => {
                flush_pending_tls_plain(client, &mut pending_client_flush_bytes).await?;
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

async fn flush_pending_tls_plain(
    client: &mut AsyncResidentTlsClient,
    pending_client_flush_bytes: &mut usize,
) -> Result<(), String> {
    if *pending_client_flush_bytes == 0 {
        return Ok(());
    }
    client
        .flush_plain("write client payload to proxy TLS")
        .await?;
    *pending_client_flush_bytes = 0;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_plain_relay_uses_coalesced_flush_threshold() {
        assert!(TLS_PLAIN_RELAY_FLUSH_BYTES >= 64 * 1024);
        assert!(TLS_PLAIN_RELAY_FLUSH_DELAY <= Duration::from_millis(5));
    }
}
