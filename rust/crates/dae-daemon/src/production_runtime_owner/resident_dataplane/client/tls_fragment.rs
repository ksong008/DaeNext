use super::*;

pub(in crate::production_runtime_owner::resident_dataplane) enum ResidentTcpStream {
    Plain(TcpStream),
    Fragmenting {
        tcp: TcpStream,
        options: TlsFragmentOptions,
    },
}

impl ResidentTcpStream {
    pub(super) fn new(tcp: TcpStream, options: Option<TlsFragmentOptions>) -> Self {
        match options {
            Some(options) => Self::Fragmenting { tcp, options },
            None => Self::Plain(tcp),
        }
    }

    pub(super) fn raw_mut(&mut self) -> &mut TcpStream {
        match self {
            Self::Plain(tcp) | Self::Fragmenting { tcp, .. } => tcp,
        }
    }
}

impl Read for ResidentTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.raw_mut().read(buf)
    }
}

impl Write for ResidentTcpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(tcp) => tcp.write(buf),
            Self::Fragmenting { tcp, options } => {
                let fragmented = fragment_tls_write(buf, options)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
                write_tls_fragmented_bytes(tcp, &fragmented.bytes, &fragmented.report, options)?;
                Ok(buf.len())
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.raw_mut().flush()
    }
}

fn write_tls_fragmented_bytes(
    tcp: &mut TcpStream,
    bytes: &[u8],
    report: &dae_outbound::shared_transport::TlsFragmentWriteReport,
    options: &TlsFragmentOptions,
) -> std::io::Result<()> {
    if !report.fragmented || !options.interval_enabled() {
        tcp.write_all(bytes)?;
        return Ok(());
    }

    let mut offset = 0;
    for payload_len in &report.fragment_payload_lens {
        let record_len = TLS_RECORD_HEADER_LEN + payload_len;
        tcp.write_all(&bytes[offset..offset + record_len])?;
        offset += record_len;
        thread::sleep(Duration::from_millis(options.min_interval_ms));
    }
    if offset < bytes.len() {
        tcp.write_all(&bytes[offset..])?;
    }
    Ok(())
}

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
            Self::Fragmenting(stream) => &mut stream.tcp,
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
    tcp: TokioTcpStream,
    options: TlsFragmentOptions,
    pending: Vec<u8>,
    pending_offset: usize,
}

impl AsyncTlsFragmentingTcpStream {
    fn new(tcp: TokioTcpStream, options: TlsFragmentOptions) -> Self {
        Self {
            tcp,
            options,
            pending: Vec::new(),
            pending_offset: 0,
        }
    }

    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.pending_offset < self.pending.len() {
            let chunk = &self.pending[self.pending_offset..];
            match Pin::new(&mut self.tcp).poll_write(cx, chunk) {
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

impl AsyncRead for AsyncTlsFragmentingTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.tcp).poll_read(cx, buf)
    }
}

impl AsyncWrite for AsyncTlsFragmentingTcpStream {
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
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.tcp).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.tcp).poll_shutdown(cx),
            other => other,
        }
    }
}
