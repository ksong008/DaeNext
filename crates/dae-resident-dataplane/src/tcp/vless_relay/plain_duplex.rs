use std::sync::atomic::{AtomicBool, Ordering};

use super::*;

pub(crate) async fn relay_tcp_over_vless_plain_async(
    inbound: &mut TokioTcpStream,
    proxy: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    stop: SharedResidentStopSignal,
    initial_payload: Vec<u8>,
    metrics: &ResidentDataplaneMetrics,
) -> Result<RelayStats, RelayError> {
    let (progress, activity) = resident_duplex_progress();
    if !initial_payload.is_empty() {
        proxy.write_all(&initial_payload).await.map_err(|err| {
            RelayError::new(
                format!("write sniffed client payload to VLESS plain TCP: {err}"),
                &RelayStats::default(),
            )
        })?;
        proxy.flush().await.map_err(|err| {
            RelayError::new(
                format!("flush sniffed client payload to VLESS plain TCP: {err}"),
                &RelayStats::default(),
            )
        })?;
        progress.record_upload(initial_payload.len());
        metrics.add_upload(initial_payload.len());
    }
    drop(initial_payload);

    let response_header_stripped = Arc::new(AtomicBool::new(false));
    let (inbound_read, inbound_write) = tokio::io::split(&mut *inbound);
    let (proxy_read, proxy_write) = tokio::io::split(&mut *proxy);
    let upload_progress = progress.clone();
    let upload = async move {
        let mut inbound_read = inbound_read;
        let mut proxy_write = proxy_write;
        let mut buffer = [0_u8; VLESS_RELAY_BUFFER_SIZE];
        loop {
            let read = match inbound_read.read(&mut buffer).await {
                Ok(0) => {
                    let _ = proxy_write.shutdown().await;
                    return Ok(());
                }
                Ok(read) => read,
                Err(err) if is_graceful_stream_close_error(&err) => {
                    let _ = proxy_write.shutdown().await;
                    return Ok(());
                }
                Err(err) => return Err(format!("read inbound TCP: {err}")),
            };
            proxy_write
                .write_all(&buffer[..read])
                .await
                .map_err(|err| format!("write client payload to VLESS plain TCP: {err}"))?;
            proxy_write
                .flush()
                .await
                .map_err(|err| format!("flush client payload to VLESS plain TCP: {err}"))?;
            upload_progress.record_upload(read);
            metrics.add_upload(read);
        }
    };
    let download_progress = progress.clone();
    let download_header_state = Arc::clone(&response_header_stripped);
    let download = async move {
        let mut inbound_write = inbound_write;
        let mut proxy_read = proxy_read;
        let mut stripper = VlessResponseStripper::default();
        let mut buffer = [0_u8; VLESS_RELAY_BUFFER_SIZE];
        loop {
            let read = proxy_read
                .read(&mut buffer)
                .await
                .map_err(|err| format!("read VLESS plain TCP: {err}"))?;
            if read == 0 {
                let _ = inbound_write.shutdown().await;
                return Ok(());
            }
            let payload = stripper.consume(&buffer[..read])?;
            download_header_state.store(stripper.done, Ordering::Release);
            if !payload.is_empty() {
                inbound_write
                    .write_all(&payload)
                    .await
                    .map_err(|err| format!("write VLESS plain TCP payload to client: {err}"))?;
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
