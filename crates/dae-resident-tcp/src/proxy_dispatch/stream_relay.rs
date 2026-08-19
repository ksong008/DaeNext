use super::*;

const QUIC_STREAM_RELAY_BUFFER_SIZE: usize = 16 * 1024;

pub async fn relay_tcp_over_quic_stream_async(
    inbound: &mut TokioTcpStream,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    stop: SharedResidentStopSignal,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let (progress, activity) = resident_duplex_progress();
    let (inbound_read, inbound_write) = inbound.split();
    let upload = relay_quic_stream_upload(inbound_read, send, progress.clone(), metrics);
    let download = relay_quic_stream_download(recv, inbound_write, progress.clone(), metrics);
    run_resident_duplex_relay(
        Box::pin(upload),
        Box::pin(download),
        stop,
        &progress,
        activity,
        "resident QUIC stream relay idle timeout",
        None,
    )
    .await
}

async fn relay_quic_stream_upload(
    mut inbound: tokio::net::tcp::ReadHalf<'_>,
    send: &mut quinn::SendStream,
    progress: ResidentDuplexProgress,
    metrics: &ResidentDataplaneMetrics,
) -> Result<(), String> {
    let mut buffer = [0_u8; QUIC_STREAM_RELAY_BUFFER_SIZE];
    loop {
        let read = match inbound.read(&mut buffer).await {
            Ok(0) => {
                let _ = send.finish();
                return Ok(());
            }
            Ok(read) => read,
            Err(err) if is_graceful_stream_close_error(&err) => {
                let _ = send.finish();
                return Ok(());
            }
            Err(err) => return Err(format!("read inbound TCP for QUIC stream relay: {err}")),
        };
        send.write_all(&buffer[..read])
            .await
            .map_err(|err| format!("write client payload to QUIC stream: {err}"))?;
        progress.record_upload(read);
        metrics.add_upload(read);
    }
}

async fn relay_quic_stream_download(
    recv: &mut quinn::RecvStream,
    mut inbound: tokio::net::tcp::WriteHalf<'_>,
    progress: ResidentDuplexProgress,
    metrics: &ResidentDataplaneMetrics,
) -> Result<(), String> {
    let mut buffer = [0_u8; QUIC_STREAM_RELAY_BUFFER_SIZE];
    loop {
        let Some(read) = recv
            .read(&mut buffer)
            .await
            .map_err(|err| format!("read QUIC stream payload: {err}"))?
        else {
            let _ = inbound.shutdown().await;
            return Ok(());
        };
        if let Err(err) = inbound.write_all(&buffer[..read]).await {
            if is_graceful_stream_close_error(&err) {
                return Ok(());
            }
            return Err(format!("write QUIC stream payload to client: {err}"));
        }
        progress.record_download(read);
        metrics.add_download(read);
    }
}
