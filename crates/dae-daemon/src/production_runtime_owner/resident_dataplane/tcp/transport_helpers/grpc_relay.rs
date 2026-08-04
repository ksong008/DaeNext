use super::*;
pub(crate) async fn relay_tcp_over_grpc_h2(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    send_stream: &mut h2::SendStream<Bytes>,
    response: &mut GrpcH2Response,
    stop: SharedResidentStopSignal,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
    strip_vless_response_header: bool,
) -> Result<DirectTcpRelayStats, String> {
    let (progress, activity) = resident_duplex_progress();
    if stats.client_to_direct != 0 {
        progress.record_upload(stats.client_to_direct);
    }
    if stats.direct_to_client != 0 {
        progress.record_download(stats.direct_to_client);
    }
    let (inbound_read, inbound_write) = tokio::io::split(&mut *inbound);
    let upload_progress = progress.clone();
    let upload = async move {
        let mut inbound_read = inbound_read;
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = match inbound_read.read(&mut buffer).await {
                Ok(0) => {
                    send_h2_data(send_stream, Bytes::new(), true).await?;
                    return Ok(());
                }
                Ok(read) => read,
                Err(err) if is_graceful_stream_close_error(&err) => {
                    send_h2_data(send_stream, Bytes::new(), true).await?;
                    return Ok(());
                }
                Err(err) => return Err(format!("read inbound TCP for gRPC relay: {err}")),
            };
            send_grpc_hunk(send_stream, &buffer[..read], false).await?;
            upload_progress.record_upload(read);
            metrics.add_upload(read);
        }
    };
    let download_progress = progress.clone();
    let download = async move {
        let mut inbound_write = inbound_write;
        let mut response_buf = GrpcHunkReadBuffer::default();
        let mut vless_response_stripper =
            strip_vless_response_header.then(VlessResponseStripper::default);
        loop {
            let Some(bytes) = response.next_data().await? else {
                if !response_buf.is_empty() {
                    return Err("gRPC response stream ended with partial hunk".to_owned());
                }
                let _ = inbound_write.shutdown().await;
                return Ok(());
            };
            response_buf.extend_from_slice(&bytes);
            while let Some(payload) = response_buf.next_payload()? {
                if let Some(stripper) = vless_response_stripper.as_mut() {
                    let payload = stripper.consume(payload)?;
                    if !payload.is_empty() {
                        inbound_write
                            .write_all(&payload)
                            .await
                            .map_err(|err| format!("write gRPC response to inbound: {err}"))?;
                        download_progress.record_download(payload.len());
                        metrics.add_download(payload.len());
                    }
                } else if !payload.is_empty() {
                    inbound_write
                        .write_all(payload)
                        .await
                        .map_err(|err| format!("write gRPC response to inbound: {err}"))?;
                    download_progress.record_download(payload.len());
                    metrics.add_download(payload.len());
                }
            }
        }
    };
    run_resident_duplex_relay(
        Box::pin(upload),
        Box::pin(download),
        stop,
        &progress,
        activity,
        "resident gRPC relay idle timeout",
        None,
    )
    .await
}
