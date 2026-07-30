use super::client_io::{
    read_xhttp_download_data, send_xhttp_packet_up_request, send_xhttp_stream_data,
};
use super::*;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const XHTTP_UPLOAD_READ_CHUNK: usize = 16 * 1024;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp_over_xhttp_packet_up(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    upload: &mut XhttpUploadClient,
    download: &mut XhttpDownloadClient,
    session_id: &str,
    mut seq: u64,
    stop: SharedResidentStopSignal,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
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
    let upload_direction = async move {
        let mut inbound_read = inbound_read;
        let mut buffer = BytesMut::with_capacity(XHTTP_UPLOAD_READ_CHUNK);
        loop {
            match read_xhttp_upload_chunk(&mut inbound_read, &mut buffer).await {
                Ok(None) => return Ok(()),
                Ok(Some(chunk)) => {
                    let read = chunk.len();
                    send_xhttp_packet_up_request(upload, session_id, seq, chunk).await?;
                    seq = seq.saturating_add(1);
                    upload_progress.record_upload(read);
                    metrics.add_upload(read);
                }
                Err(err) if is_graceful_stream_close_error(&err) => return Ok(()),
                Err(err) => return Err(format!("read inbound TCP for xHTTP relay: {err}")),
            }
        }
    };
    let download_progress = progress.clone();
    let download_direction = async move {
        let mut inbound_write = inbound_write;
        let mut response_stripper = VlessResponseStripper::default();
        loop {
            let Some(bytes) = read_xhttp_download_data(download).await? else {
                let _ = inbound_write.shutdown().await;
                return Ok(());
            };
            let payload = response_stripper.consume(&bytes)?;
            if !payload.is_empty() {
                inbound_write
                    .write_all(&payload)
                    .await
                    .map_err(|err| format!("write xHTTP response to inbound: {err}"))?;
                download_progress.record_download(payload.len());
                metrics.add_download(payload.len());
            }
        }
    };
    run_resident_duplex_relay(
        Box::pin(upload_direction),
        Box::pin(download_direction),
        stop,
        &progress,
        activity,
        "resident xHTTP relay idle timeout",
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp_over_xhttp_stream(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    upload: &mut XhttpStreamUploadClient,
    download: &mut XhttpDownloadClient,
    stop: SharedResidentStopSignal,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
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
    let upload_direction = async move {
        let mut inbound_read = inbound_read;
        let mut buffer = BytesMut::with_capacity(XHTTP_UPLOAD_READ_CHUNK);
        loop {
            match read_xhttp_upload_chunk(&mut inbound_read, &mut buffer).await {
                Ok(None) => {
                    send_xhttp_stream_data(upload, Bytes::new(), true).await?;
                    return Ok(());
                }
                Ok(Some(chunk)) => {
                    let read = chunk.len();
                    send_xhttp_stream_data(upload, chunk, false).await?;
                    upload_progress.record_upload(read);
                    metrics.add_upload(read);
                }
                Err(err) if is_graceful_stream_close_error(&err) => {
                    send_xhttp_stream_data(upload, Bytes::new(), true).await?;
                    return Ok(());
                }
                Err(err) => {
                    return Err(format!("read inbound TCP for xHTTP stream relay: {err}"));
                }
            }
        }
    };
    let download_progress = progress.clone();
    let download_direction = async move {
        let mut inbound_write = inbound_write;
        let mut response_stripper = VlessResponseStripper::default();
        loop {
            let Some(bytes) = read_xhttp_download_data(download).await? else {
                let _ = inbound_write.shutdown().await;
                return Ok(());
            };
            let payload = response_stripper.consume(&bytes)?;
            if !payload.is_empty() {
                inbound_write
                    .write_all(&payload)
                    .await
                    .map_err(|err| format!("write xHTTP stream response to inbound: {err}"))?;
                download_progress.record_download(payload.len());
                metrics.add_download(payload.len());
            }
        }
    };
    run_resident_duplex_relay(
        Box::pin(upload_direction),
        Box::pin(download_direction),
        stop,
        &progress,
        activity,
        "resident xHTTP stream relay idle timeout",
        None,
    )
    .await
}

async fn read_xhttp_upload_chunk(
    inbound: &mut (impl AsyncRead + Unpin),
    buffer: &mut BytesMut,
) -> std::io::Result<Option<Bytes>> {
    buffer.reserve(XHTTP_UPLOAD_READ_CHUNK);
    let read = inbound.read_buf(buffer).await?;
    if read == 0 {
        return Ok(None);
    }
    Ok(Some(buffer.split_to(read).freeze()))
}
