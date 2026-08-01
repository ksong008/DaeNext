use super::client_io::{read_xhttp_download_data, send_xhttp_stream_data};
use super::*;
use bytes::{Bytes, BytesMut};
use futures_util::FutureExt;
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
        let mut pipeline = XhttpPacketUpPipeline::for_upload(upload);
        let mut inbound = XhttpUploadChunkReader::new(inbound_read);
        loop {
            match inbound.read_chunk(pipeline.max_post_bytes()).await {
                Ok(None) => return pipeline.finish().await,
                Ok(Some(chunk)) => {
                    let read = chunk.len();
                    pipeline.send(upload, session_id, &mut seq, chunk).await?;
                    upload_progress.record_upload(read);
                    metrics.add_upload(read);
                }
                Err(err) if is_graceful_stream_close_error(&err) => {
                    return pipeline.finish().await;
                }
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
            match read_xhttp_stream_upload_chunk(&mut inbound_read, &mut buffer).await {
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

async fn read_xhttp_stream_upload_chunk(
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

struct XhttpUploadChunkReader<R> {
    inbound: R,
    buffer: BytesMut,
    terminal_error: Option<std::io::Error>,
    eof: bool,
}

impl<R> XhttpUploadChunkReader<R>
where
    R: AsyncRead + Unpin,
{
    fn new(inbound: R) -> Self {
        Self {
            inbound,
            buffer: BytesMut::with_capacity(XHTTP_UPLOAD_READ_CHUNK),
            terminal_error: None,
            eof: false,
        }
    }

    async fn read_chunk(&mut self, max_chunk_bytes: usize) -> std::io::Result<Option<Bytes>> {
        let max_chunk_bytes = max_chunk_bytes.max(1);
        if self.buffer.is_empty() {
            if let Some(error) = self.terminal_error.take() {
                return Err(error);
            }
            if self.eof {
                return Ok(None);
            }
            self.reserve_read_capacity(max_chunk_bytes);
            let read = self.inbound.read_buf(&mut self.buffer).await?;
            if read == 0 {
                self.eof = true;
                return Ok(None);
            }
        }

        self.coalesce_ready_data(max_chunk_bytes);
        let take = self.buffer.len().min(max_chunk_bytes);
        Ok(Some(self.buffer.split_to(take).freeze()))
    }

    fn coalesce_ready_data(&mut self, max_chunk_bytes: usize) {
        while self.buffer.len() < max_chunk_bytes && self.terminal_error.is_none() && !self.eof {
            self.reserve_read_capacity(max_chunk_bytes);
            match self.inbound.read_buf(&mut self.buffer).now_or_never() {
                Some(Ok(0)) => self.eof = true,
                Some(Ok(_)) => {}
                Some(Err(error)) => self.terminal_error = Some(error),
                None => break,
            }
        }
    }

    fn reserve_read_capacity(&mut self, max_chunk_bytes: usize) {
        let remaining = max_chunk_bytes.saturating_sub(self.buffer.len());
        self.buffer
            .reserve(remaining.clamp(1, XHTTP_UPLOAD_READ_CHUNK));
    }
}

#[cfg(test)]
#[path = "relay/tests.rs"]
mod tests;
