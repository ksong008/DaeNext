use super::*;

pub(in crate::production_runtime_owner::resident_dataplane) enum AsyncResidentTcpStream {
    Plain(TokioTcpStream),
    Fragmenting(AsyncTlsFragmentingTcpStream),
}

impl AsyncResidentTcpStream {
    pub(super) fn new(tcp: TokioTcpStream, options: Option<TlsFragmentOptions>) -> Self {
        match options {
            Some(options) => Self::Fragmenting(AsyncTlsFragmentingTcpStream::new(tcp, options)),
            None => Self::Plain(tcp),
        }
    }

    pub(super) fn raw_mut(&mut self) -> &mut TokioTcpStream {
        match self {
            Self::Plain(tcp) => tcp,
            Self::Fragmenting(stream) => stream.raw_mut(),
        }
    }
}

impl AsyncRead for AsyncResidentTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(tcp) => Pin::new(tcp).poll_read(cx, buf),
            Self::Fragmenting(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AsyncResidentTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Plain(tcp) => Pin::new(tcp).poll_write(cx, buf),
            Self::Fragmenting(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(tcp) => Pin::new(tcp).poll_flush(cx),
            Self::Fragmenting(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(tcp) => Pin::new(tcp).poll_shutdown(cx),
            Self::Fragmenting(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub(in crate::production_runtime_owner::resident_dataplane) struct AsyncTlsFragmentingTcpStream {
    inner: AsyncTlsFragmentingWriter<TokioTcpStream>,
}

impl AsyncTlsFragmentingTcpStream {
    fn new(tcp: TokioTcpStream, options: TlsFragmentOptions) -> Self {
        Self {
            inner: AsyncTlsFragmentingWriter::new(tcp, options),
        }
    }

    fn raw_mut(&mut self) -> &mut TokioTcpStream {
        &mut self.inner.inner
    }
}

pub(in crate::production_runtime_owner::resident_dataplane) struct AsyncTlsFragmentingWriter<S> {
    inner: S,
    options: TlsFragmentOptions,
    pending: Vec<u8>,
    pending_offset: usize,
}

impl<S> AsyncTlsFragmentingWriter<S> {
    fn new(inner: S, options: TlsFragmentOptions) -> Self {
        Self {
            inner,
            options,
            pending: Vec::new(),
            pending_offset: 0,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncTlsFragmentingWriter<S> {
    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.pending_offset < self.pending.len() {
            let chunk = &self.pending[self.pending_offset..];
            match Pin::new(&mut self.inner).poll_write(cx, chunk) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "write tls-fragmented TCP underlay: wrote zero bytes",
                    )));
                }
                Poll::Ready(Ok(written)) => {
                    self.pending_offset += written;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending.clear();
        self.pending_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for AsyncTlsFragmentingWriter<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for AsyncTlsFragmentingWriter<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }

        let fragmented = fragment_tls_write(buf, &self.options)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
        self.pending = fragmented.bytes;
        self.pending_offset = 0;

        match self.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Ready(Ok(buf.len())),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

impl AsyncRead for AsyncTlsFragmentingTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for AsyncTlsFragmentingTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests;
