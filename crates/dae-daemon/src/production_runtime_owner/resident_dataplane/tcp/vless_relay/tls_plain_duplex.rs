use std::sync::atomic::{AtomicBool, Ordering};

use super::*;

pub(super) async fn relay_tcp_over_vless_tls_plain_duplex(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    client: &mut AsyncVlessTlsClient,
    stop: SharedResidentStopSignal,
    initial_payload: Vec<u8>,
    metrics: &ResidentDataplaneMetrics,
) -> Result<RelayStats, RelayError> {
    let (progress, activity) = resident_duplex_progress();
    if !initial_payload.is_empty() {
        client
            .write_plain_all(
                &initial_payload,
                "write sniffed client payload to proxy TLS",
            )
            .await
            .map_err(|error| RelayError::new(error, &RelayStats::default()))?;
        progress.record_upload(initial_payload.len());
        metrics.add_upload(initial_payload.len());
    }
    drop(initial_payload);

    let response_header_stripped = Arc::new(AtomicBool::new(false));
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
                        Err(err) => return Err(format!("read inbound TCP: {err}")),
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
    let download_header_state = Arc::clone(&response_header_stripped);
    let download = async move {
        let mut inbound_write = inbound_write;
        let mut client_read = client_read;
        let mut stripper = VlessResponseStripper::default();
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = match client_read.read(&mut buffer).await {
                Ok(0) => {
                    let _ = inbound_write.shutdown().await;
                    return Ok(());
                }
                Ok(read) => read,
                Err(err) => {
                    let snapshot = download_progress.snapshot();
                    let current = RelayStats {
                        client_to_proxy: snapshot.client_to_direct,
                        proxy_to_client: snapshot.direct_to_client,
                        response_header_stripped: download_header_state.load(Ordering::Acquire),
                        ..RelayStats::default()
                    };
                    if is_graceful_vless_response_tls_plain_close_error(&err, &current) {
                        let _ = inbound_write.shutdown().await;
                        return Ok(());
                    }
                    return Err(format!("read VLESS TLS plaintext: {err}"));
                }
            };
            let payload = stripper.consume(&buffer[..read])?;
            download_header_state.store(stripper.done, Ordering::Release);
            if !payload.is_empty() {
                inbound_write
                    .write_all(&payload)
                    .await
                    .map_err(|err| format!("write VLESS payload to client: {err}"))?;
                download_progress.record_download(payload.len());
                metrics.add_download(payload.len());
            }
        }
    };

    let result = run_resident_duplex_relay(
        Box::pin(upload),
        Box::pin(download),
        stop,
        &progress,
        activity,
        "resident TCP relay idle timeout",
        Some(RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT),
    )
    .await;
    let snapshot = progress.snapshot();
    let stats = RelayStats {
        client_to_proxy: snapshot.client_to_direct,
        proxy_to_client: snapshot.direct_to_client,
        response_header_stripped: response_header_stripped.load(Ordering::Acquire),
        ..RelayStats::default()
    };
    result
        .map(|_| stats.clone())
        .map_err(|error| RelayError::new(error, &stats))
}
