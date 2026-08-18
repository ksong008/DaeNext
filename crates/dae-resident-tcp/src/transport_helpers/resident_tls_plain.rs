use super::*;

pub const TLS_PLAIN_RELAY_FLUSH_BYTES: usize = 128 * 1024;
pub const TLS_PLAIN_RELAY_FLUSH_DELAY: Duration = Duration::from_millis(1);

pub async fn relay_tcp_over_resident_tls_plain_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    client: &mut AsyncResidentTlsClient,
    stop: SharedResidentStopSignal,
    metrics: &ResidentDataplaneMetrics,
    leftover: Vec<u8>,
) -> Result<DirectTcpRelayStats, String> {
    let (progress, activity) = resident_duplex_progress();
    let (inbound_read, inbound_write) = tokio::io::split(&mut *inbound);
    let (client_read, client_write) = tokio::io::split(&mut *client);
    let upload_progress = progress.clone();
    let upload = async move {
        let mut inbound_read = inbound_read;
        let mut client_write = client_write;
        let mut buffer = [0_u8; 16 * 1024];
        let mut pending_flush_bytes = 0_usize;
        let mut pending_flush_deadline = None;
        loop {
            tokio::select! {
                read = inbound_read.read(&mut buffer) => {
                    let read = match read {
                        Ok(0) => {
                            flush_tls_plain_write_half(
                                &mut client_write,
                                &mut pending_flush_bytes,
                                &mut pending_flush_deadline,
                            ).await?;
                            let _ = client_write.shutdown().await;
                            return Ok(());
                        }
                        Ok(read) => read,
                        Err(err) if is_graceful_stream_close_error(&err) => {
                            flush_tls_plain_write_half(
                                &mut client_write,
                                &mut pending_flush_bytes,
                                &mut pending_flush_deadline,
                            ).await?;
                            let _ = client_write.shutdown().await;
                            return Ok(());
                        }
                        Err(err) => return Err(format!("read inbound TCP for proxy TLS relay: {err}")),
                    };
                    client_write
                        .write_all(&buffer[..read])
                        .await
                        .map_err(|err| format!("write client payload to proxy TLS: {err}"))?;
                    note_pending_tls_plain_flush(
                        &mut pending_flush_bytes,
                        &mut pending_flush_deadline,
                        read,
                    );
                    if pending_flush_bytes >= TLS_PLAIN_RELAY_FLUSH_BYTES {
                        flush_tls_plain_write_half(
                            &mut client_write,
                            &mut pending_flush_bytes,
                            &mut pending_flush_deadline,
                        ).await?;
                    }
                    upload_progress.record_upload(read);
                    metrics.add_upload(read);
                }
                _ = time::sleep_until(tls_plain_flush_deadline(pending_flush_deadline)), if pending_flush_deadline.is_some() => {
                    flush_tls_plain_write_half(
                        &mut client_write,
                        &mut pending_flush_bytes,
                        &mut pending_flush_deadline,
                    ).await?;
                }
            }
        }
    };
    let download_progress = progress.clone();
    let download = async move {
        let mut inbound_write = inbound_write;
        let mut client_read = client_read;
        let mut buffer = [0_u8; 16 * 1024];
        if !leftover.is_empty() {
            inbound_write
                .write_all(&leftover)
                .await
                .map_err(|err| format!("write proxy TLS leftover to client: {err}"))?;
        }
        loop {
            let read = match client_read.read(&mut buffer).await {
                Ok(0) => {
                    let _ = inbound_write.shutdown().await;
                    return Ok(());
                }
                Ok(read) => read,
                Err(err) if is_graceful_tls_plain_close_error(&err) => {
                    let _ = inbound_write.shutdown().await;
                    return Ok(());
                }
                Err(err) => return Err(format!("read proxy TLS plaintext: {err}")),
            };
            if let Err(err) = inbound_write.write_all(&buffer[..read]).await {
                if is_graceful_stream_close_error(&err) {
                    return Ok(());
                }
                return Err(format!("write proxy TLS payload to client: {err}"));
            }
            download_progress.record_download(read);
            metrics.add_download(read);
        }
    };
    run_resident_duplex_relay(
        Box::pin(upload),
        Box::pin(download),
        stop,
        &progress,
        activity,
        "resident proxy TLS relay idle timeout",
        None,
    )
    .await
}

pub async fn flush_tls_plain_write_half<W>(
    writer: &mut W,
    pending_bytes: &mut usize,
    deadline: &mut Option<Instant>,
) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    if *pending_bytes == 0 {
        *deadline = None;
        return Ok(());
    }
    writer
        .flush()
        .await
        .map_err(|err| format!("flush write client payload to proxy TLS: {err}"))?;
    *pending_bytes = 0;
    *deadline = None;
    Ok(())
}

pub fn note_pending_tls_plain_flush(
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

pub fn tls_plain_flush_deadline(deadline: Option<Instant>) -> time::Instant {
    time::Instant::from_std(deadline.unwrap_or_else(Instant::now))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::assertions_on_constants)]
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
