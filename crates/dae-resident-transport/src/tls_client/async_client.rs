use super::*;

impl AsyncVlessTlsClient {
    fn tls(&self) -> &tokio_boring::SslStream<AsyncResidentTcpStream> {
        match &self.engine {
            AsyncVlessTlsEngine::Boring { tls } | AsyncVlessTlsEngine::RealityBoring { tls } => tls,
        }
    }

    fn tls_mut(&mut self) -> &mut tokio_boring::SslStream<AsyncResidentTcpStream> {
        match &mut self.engine {
            AsyncVlessTlsEngine::Boring { tls } | AsyncVlessTlsEngine::RealityBoring { tls } => tls,
        }
    }

    pub fn enable_vision_record_handoff(&mut self) {
        self.tls_mut().get_mut().enable_vision_record_handoff();
    }

    pub fn poll_plain_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(self.tls_mut()).poll_read(cx, buf);
        record_ssl_read(match &result {
            Poll::Ready(Ok(())) => Some(buf.filled().len().saturating_sub(before)),
            Poll::Ready(Err(_)) | Poll::Pending => None,
        });
        result
    }

    pub fn poll_plain_write(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(self.tls_mut()).poll_write(cx, buf);
        record_ssl_write(match &result {
            Poll::Ready(Ok(written)) => Some(*written),
            Poll::Ready(Err(_)) | Poll::Pending => None,
        });
        result
    }

    pub fn poll_plain_write_vectored(
        &mut self,
        cx: &mut Context<'_>,
        buffers: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(self.tls_mut()).poll_write_vectored(cx, buffers);
        record_ssl_write(match &result {
            Poll::Ready(Ok(written)) => Some(*written),
            Poll::Ready(Err(_)) | Poll::Pending => None,
        });
        result
    }

    pub fn plain_is_write_vectored(&self) -> bool {
        self.tls().is_write_vectored()
    }

    pub fn poll_plain_flush(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(self.tls_mut()).poll_flush(cx)
    }

    pub fn poll_plain_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(self.tls_mut()).poll_shutdown(cx)
    }

    pub fn poll_raw_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let raw = self.tls_mut().get_mut().raw_mut();
        Pin::new(raw).poll_read(cx, buf)
    }

    pub fn take_vision_record_handoff(&mut self) -> bool {
        self.tls_mut().get_mut().take_vision_record_handoff()
    }

    pub fn poll_raw_write(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let raw = self.tls_mut().get_mut().raw_mut();
        Pin::new(raw).poll_write(cx, buf)
    }

    pub fn poll_raw_flush(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let raw = self.tls_mut().get_mut().raw_mut();
        Pin::new(raw).poll_flush(cx)
    }

    pub fn poll_raw_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let raw = self.tls_mut().get_mut().raw_mut();
        Pin::new(raw).poll_shutdown(cx)
    }

    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.tls().ssl().selected_alpn_protocol()
    }

    pub async fn write_plain_all(&mut self, payload: &[u8], label: &str) -> Result<(), String> {
        self.write_plain_all_buffered(payload, label).await?;
        self.flush_plain(label).await
    }

    pub async fn write_plain_all_buffered(
        &mut self,
        payload: &[u8],
        label: &str,
    ) -> Result<(), String> {
        self.tls_mut()
            .write_all(payload)
            .await
            .map_err(|err| format!("{label}: {err}"))
    }

    pub async fn flush_plain(&mut self, label: &str) -> Result<(), String> {
        self.tls_mut()
            .flush()
            .await
            .map_err(|err| format!("flush {label}: {err}"))
    }

    pub async fn shutdown(&mut self) {
        let _ = self.tls_mut().shutdown().await;
    }
}

impl AsyncRead for AsyncVlessTlsClient {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.poll_plain_read(cx, buf)
    }
}

impl AsyncWrite for AsyncVlessTlsClient {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.poll_plain_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        self.poll_plain_write_vectored(cx, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.plain_is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_plain_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_plain_shutdown(cx)
    }
}
