use super::client_io::{read_xhttp_download_data, send_xhttp_stream_data};
use super::*;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const XHTTP_UPLOAD_READ_CHUNK: usize = 16 * 1024;

pub fn spawn_xhttp_packet_up_payload_stream(parts: XhttpPacketUpParts) -> SpawnedLogicalStream {
    SpawnedLogicalStream::spawn(move |logical| drive_xhttp_packet_up_payload_stream(logical, parts))
}

pub fn spawn_xhttp_stream_payload_stream(parts: XhttpStreamParts) -> SpawnedLogicalStream {
    SpawnedLogicalStream::spawn(move |logical| drive_xhttp_stream_payload_stream(logical, parts))
}

async fn drive_xhttp_packet_up_payload_stream(
    logical: tokio::io::DuplexStream,
    parts: XhttpPacketUpParts,
) -> Result<(), String> {
    let XhttpPacketUpParts {
        session_id,
        mut upload,
        mut download,
        ..
    } = parts;
    let (mut logical_read, mut logical_write) = tokio::io::split(logical);
    let upload_direction = async {
        let mut pipeline = XhttpPacketUpPipeline::for_upload(&upload);
        let mut sequence = 0_u64;
        let mut buffer = BytesMut::with_capacity(XHTTP_UPLOAD_READ_CHUNK);
        loop {
            let Some(chunk) = read_xhttp_stream_upload_chunk(&mut logical_read, &mut buffer)
                .await
                .map_err(|error| {
                    format!("read VLESS Encryption xHTTP packet-up stream: {error}")
                })?
            else {
                pipeline.finish().await?;
                return Ok(());
            };
            pipeline
                .send(&mut upload, &session_id, &mut sequence, chunk)
                .await?;
        }
    };
    let download_direction = async {
        loop {
            let Some(bytes) = read_xhttp_download_data(&mut download).await? else {
                logical_write.shutdown().await.map_err(|error| {
                    format!("shutdown VLESS Encryption xHTTP logical stream: {error}")
                })?;
                return Ok(());
            };
            if !bytes.is_empty() {
                logical_write.write_all(&bytes).await.map_err(|error| {
                    format!("write VLESS Encryption xHTTP logical stream: {error}")
                })?;
                logical_write.flush().await.map_err(|error| {
                    format!("flush VLESS Encryption xHTTP logical stream: {error}")
                })?;
            }
        }
    };
    let result = tokio::try_join!(upload_direction, download_direction).map(|_| ());
    close_xhttp_download_client(download).await;
    close_xhttp_upload_client(upload).await;
    result
}

async fn drive_xhttp_stream_payload_stream(
    logical: tokio::io::DuplexStream,
    parts: XhttpStreamParts,
) -> Result<(), String> {
    let XhttpStreamParts {
        mut upload,
        mut download,
        ..
    } = parts;
    let (mut logical_read, mut logical_write) = tokio::io::split(logical);
    let upload_direction = async {
        let mut buffer = BytesMut::with_capacity(XHTTP_UPLOAD_READ_CHUNK);
        loop {
            let Some(chunk) = read_xhttp_stream_upload_chunk(&mut logical_read, &mut buffer)
                .await
                .map_err(|error| format!("read VLESS Encryption xHTTP stream: {error}"))?
            else {
                send_xhttp_stream_data(&mut upload, Bytes::new(), true).await?;
                return Ok(());
            };
            send_xhttp_stream_data(&mut upload, chunk, false).await?;
        }
    };
    let download_direction = async {
        loop {
            let Some(bytes) = read_xhttp_download_data(&mut download).await? else {
                logical_write.shutdown().await.map_err(|error| {
                    format!("shutdown VLESS Encryption xHTTP logical stream: {error}")
                })?;
                return Ok(());
            };
            if !bytes.is_empty() {
                logical_write.write_all(&bytes).await.map_err(|error| {
                    format!("write VLESS Encryption xHTTP logical stream: {error}")
                })?;
                logical_write.flush().await.map_err(|error| {
                    format!("flush VLESS Encryption xHTTP logical stream: {error}")
                })?;
            }
        }
    };
    let result = tokio::try_join!(upload_direction, download_direction).map(|_| ());
    close_xhttp_download_client(download).await;
    close_xhttp_stream_upload_client(upload).await;
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
