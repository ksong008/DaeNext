use super::*;
use bytes::{Bytes, BytesMut};
use futures_util::FutureExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};

const XHTTP_UPLOAD_READ_CHUNK: usize = 16 * 1024;
const XHTTP_H3_DOWNLOAD_WRITE_BUFFER: usize = 32 * 1024;

#[allow(clippy::too_many_arguments)]
pub async fn relay_tcp_over_xhttp_packet_up(
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
                Ok(None) => return finish_xhttp_packet_up_upload(&mut pipeline, upload).await,
                Ok(Some(chunk)) => {
                    let read = chunk.len();
                    pipeline.send(upload, session_id, &mut seq, chunk).await?;
                    upload_progress.record_upload(read);
                    metrics.add_upload(read);
                }
                Err(err) if is_graceful_stream_close_error(&err) => {
                    return finish_xhttp_packet_up_upload(&mut pipeline, upload).await;
                }
                Err(err) => return Err(format!("read inbound TCP for xHTTP relay: {err}")),
            }
        }
    };
    let download_progress = progress.clone();
    let download_direction = async move {
        let mut inbound_write = xhttp_download_writer(inbound_write, download);
        let mut response_stripper = VlessResponseStripper::default();
        loop {
            let Some(bytes) = read_download_flushing_pending(
                read_xhttp_download_data(download),
                &mut inbound_write,
            )
            .await?
            else {
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
        Some(RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT),
    )
    .await
}

async fn finish_xhttp_packet_up_upload(
    pipeline: &mut XhttpPacketUpPipeline,
    upload: &XhttpUploadClient,
) -> Result<(), String> {
    let result = pipeline.finish().await;
    // All POSTs have completed (or failed). This session will never upload
    // again, even if the independently owned download is still draining.
    if let XhttpUploadClient::H1 { pool, .. } = upload {
        pool.close();
    }
    result
}

#[allow(clippy::too_many_arguments)]
pub async fn relay_tcp_over_xhttp_stream(
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
        let mut inbound_write = xhttp_download_writer(inbound_write, download);
        let mut response_stripper = VlessResponseStripper::default();
        loop {
            let Some(bytes) = read_download_flushing_pending(
                read_xhttp_download_data(download),
                &mut inbound_write,
            )
            .await?
            else {
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

fn xhttp_download_writer<W: AsyncWrite>(writer: W, download: &XhttpDownloadClient) -> BufWriter<W> {
    // h3-quinn exposes individual QUIC chunks (often ~1.4 KiB). Sending each
    // straight to TCP repeats the socket/eBPF path for every small fragment.
    // Only H3 needs this fixed buffer; capacity zero keeps H1/H2 unbuffered.
    let capacity = if matches!(
        download,
        XhttpDownloadClient::H3 { .. } | XhttpDownloadClient::H3StreamOne { .. }
    ) {
        XHTTP_H3_DOWNLOAD_WRITE_BUFFER
    } else {
        0
    };
    BufWriter::with_capacity(capacity, writer)
}

async fn read_download_flushing_pending<W: AsyncWrite + Unpin>(
    read: impl std::future::Future<Output = Result<Option<Bytes>, String>>,
    writer: &mut BufWriter<W>,
) -> Result<Option<Bytes>, String> {
    // There is nothing to flush on an empty buffer. This also preserves the
    // ordinary single-await read path for the zero-capacity H1/H2 writer.
    if writer.buffer().is_empty() {
        return read.await;
    }
    tokio::pin!(read);
    let result = match read.as_mut().now_or_never() {
        Some(result) => result,
        None => {
            // Never wait for another network chunk while retaining a response:
            // this also avoids adding latency or stalling request/response IO.
            writer
                .flush()
                .await
                .map_err(|err| format!("flush xHTTP download to inbound: {err}"))?;
            read.await
        }
    };
    if !matches!(&result, Ok(Some(_))) {
        // Deliver previously accepted data before propagating EOF or an error.
        writer
            .flush()
            .await
            .map_err(|err| format!("flush xHTTP download to inbound: {err}"))?;
    }
    result
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
#[path = "xhttp_relay/tests.rs"]
mod tests;
