use std::io::{ErrorKind, IoSlice};

use tokio::io::{AsyncWrite, AsyncWriteExt};

pub async fn write_all_vectored_header_payload(
    stream: &mut (impl AsyncWrite + Unpin),
    header: &[u8],
    payload: &[u8],
) -> std::io::Result<()> {
    if !stream.is_write_vectored() {
        let mut frame = Vec::with_capacity(header.len().saturating_add(payload.len()));
        frame.extend_from_slice(header);
        frame.extend_from_slice(payload);
        return stream.write_all(&frame).await;
    }
    let mut header_offset = 0;
    let mut payload_offset = 0;
    while header_offset < header.len() || payload_offset < payload.len() {
        let written = if header_offset < header.len() {
            stream
                .write_vectored(&[
                    IoSlice::new(&header[header_offset..]),
                    IoSlice::new(&payload[payload_offset..]),
                ])
                .await?
        } else {
            stream.write(&payload[payload_offset..]).await?
        };
        if written == 0 {
            return Err(std::io::Error::from(ErrorKind::WriteZero));
        }
        let header_remaining = header.len() - header_offset;
        let header_written = written.min(header_remaining);
        header_offset += header_written;
        payload_offset += written - header_written;
    }
    Ok(())
}
