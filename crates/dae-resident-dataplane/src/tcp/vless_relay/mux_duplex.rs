use super::*;

pub(crate) async fn relay_tcp_over_vless_mux_stream_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    logical: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    stop: SharedResidentStopSignal,
    initial_payload: Vec<u8>,
    metrics: &ResidentDataplaneMetrics,
) -> Result<RelayStats, RelayError> {
    let (progress, activity) = resident_duplex_progress();
    if !initial_payload.is_empty() {
        logical.write_all(&initial_payload).await.map_err(|err| {
            RelayError::new(
                format!("write VLESS mux initial payload: {err}"),
                &RelayStats {
                    response_header_stripped: true,
                    ..RelayStats::default()
                },
            )
        })?;
        progress.record_upload(initial_payload.len());
        metrics.add_upload(initial_payload.len());
    }
    drop(initial_payload);

    let (inbound_read, inbound_write) = tokio::io::split(&mut *inbound);
    let (logical_read, logical_write) = tokio::io::split(&mut *logical);
    let upload_progress = progress.clone();
    let upload = async move {
        let mut inbound_read = inbound_read;
        let mut logical_write = logical_write;
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = match inbound_read.read(&mut buffer).await {
                Ok(0) => {
                    logical_write
                        .shutdown()
                        .await
                        .map_err(|err| format!("shutdown VLESS mux logical upload: {err}"))?;
                    return Ok(());
                }
                Ok(read) => read,
                Err(err) if is_graceful_stream_close_error(&err) => {
                    logical_write
                        .shutdown()
                        .await
                        .map_err(|err| format!("shutdown VLESS mux logical upload: {err}"))?;
                    return Ok(());
                }
                Err(err) => return Err(format!("read inbound TCP for VLESS mux: {err}")),
            };
            logical_write
                .write_all(&buffer[..read])
                .await
                .map_err(|err| format!("write VLESS mux logical payload: {err}"))?;
            upload_progress.record_upload(read);
            metrics.add_upload(read);
        }
    };
    let download_progress = progress.clone();
    let download = async move {
        let mut inbound_write = inbound_write;
        let mut logical_read = logical_read;
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = logical_read
                .read(&mut buffer)
                .await
                .map_err(|err| format!("read VLESS mux logical stream: {err}"))?;
            if read == 0 {
                let _ = inbound_write.shutdown().await;
                return Ok(());
            }
            inbound_write
                .write_all(&buffer[..read])
                .await
                .map_err(|err| format!("write VLESS mux payload to client: {err}"))?;
            download_progress.record_download(read);
            metrics.add_download(read);
        }
    };

    let result = run_resident_duplex_relay(
        Box::pin(upload),
        Box::pin(download),
        stop,
        &progress,
        activity,
        "resident VLESS mux relay idle timeout",
        Some(RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT),
    )
    .await;
    let snapshot = progress.snapshot();
    let stats = RelayStats {
        client_to_proxy: snapshot.client_to_direct,
        proxy_to_client: snapshot.direct_to_client,
        response_header_stripped: true,
        ..RelayStats::default()
    };
    result
        .map(|_| stats.clone())
        .map_err(|error| RelayError::new(error, &stats))
}
