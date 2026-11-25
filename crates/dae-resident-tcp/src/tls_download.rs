use super::*;

pub(crate) const TLS_DOWNLOAD_INITIAL_BYTES: usize = 16 * 1024;

pub(crate) struct TlsDownloadBuffer {
    bytes: Vec<u8>,
    limit: usize,
    end: Option<std::io::Result<()>>,
}

impl TlsDownloadBuffer {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            bytes: vec![0; TLS_DOWNLOAD_INITIAL_BYTES],
            limit,
            end: None,
        }
    }

    pub(crate) async fn read(
        &mut self,
        stream: &mut (impl AsyncRead + Unpin),
    ) -> std::io::Result<&[u8]> {
        if self.limit <= TLS_DOWNLOAD_INITIAL_BYTES {
            let read = stream.read(&mut self.bytes).await?;
            return Ok(&self.bytes[..read]);
        }
        if let Some(end) = self.end.take() {
            return end.map(|()| &self.bytes[..0]);
        }
        let read = std::future::poll_fn(|cx| {
            let mut batch = ReadBuf::new(&mut self.bytes);
            while batch.remaining() != 0 {
                let before = batch.filled().len();
                let end = match Pin::new(&mut *stream).poll_read(cx, &mut batch) {
                    Poll::Ready(Ok(())) if batch.filled().len() != before => continue,
                    Poll::Ready(end) => Some(end),
                    Poll::Pending if batch.filled().is_empty() => return Poll::Pending,
                    Poll::Pending => None,
                };
                if batch.filled().is_empty() {
                    return Poll::Ready(end.unwrap_or(Ok(())).map(|()| 0));
                }
                self.end = end;
                break;
            }
            Poll::Ready(Ok(batch.filled().len()))
        })
        .await?;
        Ok(&self.bytes[..read])
    }

    pub(crate) fn grow_after_write(&mut self, read: usize) {
        if read == self.bytes.len() && read < self.limit && self.end.is_none() {
            self.bytes.resize(self.limit, 0);
        }
    }
}

pub(crate) fn tls_download_buffer_limit() -> usize {
    static LIMIT: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *LIMIT.get_or_init(|| TcpRelayResourceProfile::selected().tcp_relay_buffer_bytes())
}

#[cfg(test)]
mod tests;
