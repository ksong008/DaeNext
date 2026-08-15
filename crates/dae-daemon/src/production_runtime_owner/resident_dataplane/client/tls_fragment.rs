use super::*;
use dae_outbound::shared_transport::{TlsFragmentPlan, TlsFragmentPlanner};
use std::future::Future;
use std::time::Duration;
use tokio::io::BufReader;

const BORING_TLS_BIO_READ_BUFFER_BYTES: usize = 64 * 1024;

pub(in crate::production_runtime_owner::resident_dataplane) enum AsyncResidentTcpStream {
    Plain(TokioTcpStream),
    Fragmenting(AsyncTlsFragmentingTcpStream),
    BufferedPlain(BufReader<TokioTcpStream>),
    BufferedFragmenting(BufReader<AsyncTlsFragmentingTcpStream>),
    VisionPlain(TlsRecordBoundedReader<TokioTcpStream>),
    VisionFragmenting(TlsRecordBoundedReader<AsyncTlsFragmentingTcpStream>),
}

impl AsyncResidentTcpStream {
    pub(super) fn new(tcp: TokioTcpStream, options: Option<TlsFragmentOptions>) -> Self {
        match options {
            Some(options) => Self::Fragmenting(AsyncTlsFragmentingTcpStream::new(tcp, options)),
            None => Self::Plain(tcp),
        }
    }

    pub(super) fn new_boring(tcp: TokioTcpStream, options: Option<TlsFragmentOptions>) -> Self {
        if cfg!(feature = "test-boringssl-unbuffered-bio") {
            return Self::new(tcp, options);
        }
        match options {
            Some(options) => Self::BufferedFragmenting(BufReader::with_capacity(
                BORING_TLS_BIO_READ_BUFFER_BYTES,
                AsyncTlsFragmentingTcpStream::new(tcp, options),
            )),
            None => Self::BufferedPlain(BufReader::with_capacity(
                BORING_TLS_BIO_READ_BUFFER_BYTES,
                tcp,
            )),
        }
    }

    pub(super) fn new_vision(tcp: TokioTcpStream, options: Option<TlsFragmentOptions>) -> Self {
        match options {
            Some(options) => Self::VisionFragmenting(TlsRecordBoundedReader::new(
                AsyncTlsFragmentingTcpStream::new(tcp, options),
            )),
            None => Self::VisionPlain(TlsRecordBoundedReader::new(tcp)),
        }
    }

    pub(super) fn raw_mut(&mut self) -> &mut TokioTcpStream {
        match self {
            Self::Plain(tcp) => tcp,
            Self::Fragmenting(stream) => stream.raw_mut(),
            Self::BufferedPlain(stream) => stream.get_mut(),
            Self::BufferedFragmenting(stream) => stream.get_mut().raw_mut(),
            Self::VisionPlain(stream) => stream.inner_mut(),
            Self::VisionFragmenting(stream) => stream.inner_mut().raw_mut(),
        }
    }

    pub(super) fn enable_vision_record_handoff(&mut self) {
        match self {
            Self::VisionPlain(stream) => stream.enable_record_handoff(),
            Self::VisionFragmenting(stream) => stream.enable_record_handoff(),
            Self::Plain(_)
            | Self::Fragmenting(_)
            | Self::BufferedPlain(_)
            | Self::BufferedFragmenting(_) => {}
        }
    }

    pub(super) fn take_vision_record_handoff(&mut self) -> bool {
        match self {
            Self::VisionPlain(stream) => stream.take_record_handoff(),
            Self::VisionFragmenting(stream) => stream.take_record_handoff(),
            Self::Plain(_)
            | Self::Fragmenting(_)
            | Self::BufferedPlain(_)
            | Self::BufferedFragmenting(_) => false,
        }
    }
}

impl AsyncRead for AsyncResidentTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = match &mut *self {
            Self::Plain(tcp) => Pin::new(tcp).poll_read(cx, buf),
            Self::Fragmenting(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::BufferedPlain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::BufferedFragmenting(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::VisionPlain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::VisionFragmenting(stream) => Pin::new(stream).poll_read(cx, buf),
        };
        record_bio_read(match &result {
            Poll::Ready(Ok(())) => Some(buf.filled().len().saturating_sub(before)),
            Poll::Ready(Err(_)) | Poll::Pending => None,
        });
        result
    }
}

impl AsyncWrite for AsyncResidentTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = match &mut *self {
            Self::Plain(tcp) => Pin::new(tcp).poll_write(cx, buf),
            Self::Fragmenting(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::BufferedPlain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::BufferedFragmenting(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::VisionPlain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::VisionFragmenting(stream) => Pin::new(stream).poll_write(cx, buf),
        };
        record_bio_write(match &result {
            Poll::Ready(Ok(written)) => Some(*written),
            Poll::Ready(Err(_)) | Poll::Pending => None,
        });
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(tcp) => Pin::new(tcp).poll_flush(cx),
            Self::Fragmenting(stream) => Pin::new(stream).poll_flush(cx),
            Self::BufferedPlain(stream) => Pin::new(stream).poll_flush(cx),
            Self::BufferedFragmenting(stream) => Pin::new(stream).poll_flush(cx),
            Self::VisionPlain(stream) => Pin::new(stream).poll_flush(cx),
            Self::VisionFragmenting(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(tcp) => Pin::new(tcp).poll_shutdown(cx),
            Self::Fragmenting(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::BufferedPlain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::BufferedFragmenting(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::VisionPlain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::VisionFragmenting(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

const TLS_RECORD_HEADER_BYTES: usize = 5;

pub(in crate::production_runtime_owner::resident_dataplane) struct TlsRecordBoundedReader<S> {
    inner: S,
    header: [u8; TLS_RECORD_HEADER_BYTES],
    header_read: usize,
    payload_remaining: usize,
    handoff_gate_enabled: bool,
    handoff_blocked: bool,
}

impl<S> TlsRecordBoundedReader<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            header: [0; TLS_RECORD_HEADER_BYTES],
            header_read: 0,
            payload_remaining: 0,
            handoff_gate_enabled: false,
            handoff_blocked: false,
        }
    }

    fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    fn at_record_boundary(&self) -> bool {
        self.header_read == 0 && self.payload_remaining == 0
    }

    fn enable_record_handoff(&mut self) {
        self.handoff_gate_enabled = true;
        self.handoff_blocked = self.at_record_boundary();
    }

    fn record_handoff_ready(&self) -> bool {
        self.handoff_gate_enabled && self.handoff_blocked && self.at_record_boundary()
    }

    fn take_record_handoff(&mut self) -> bool {
        let ready = self.record_handoff_ready();
        if ready {
            self.handoff_blocked = false;
        }
        ready
    }

    fn finish_record(&mut self) {
        self.header_read = 0;
        if self.handoff_gate_enabled {
            self.handoff_blocked = true;
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TlsRecordBoundedReader<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.handoff_blocked {
            return Poll::Pending;
        }

        let reading_header = self.payload_remaining == 0;
        let limit = if reading_header {
            TLS_RECORD_HEADER_BYTES - self.header_read
        } else {
            self.payload_remaining
        };
        let mut bounded = buf.take(limit);
        match Pin::new(&mut self.inner).poll_read(cx, &mut bounded) {
            Poll::Ready(Ok(())) => {
                let read = bounded.filled().len();
                if read == 0 {
                    return Poll::Ready(Ok(()));
                }
                if reading_header {
                    let start = self.header_read;
                    self.header[start..start + read].copy_from_slice(bounded.filled());
                }
                buf.advance(read);

                if reading_header {
                    self.header_read += read;
                    if self.header_read == TLS_RECORD_HEADER_BYTES {
                        self.payload_remaining =
                            u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
                        if self.payload_remaining == 0 {
                            self.finish_record();
                        }
                    }
                } else {
                    self.payload_remaining -= read;
                    if self.payload_remaining == 0 {
                        self.finish_record();
                    }
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TlsRecordBoundedReader<S> {
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
    planner: TlsFragmentPlanner,
    pending_plan: Option<TlsFragmentPlan>,
    pending_segment: usize,
    pending_offset: usize,
    pending_delay: Option<Pin<Box<time::Sleep>>>,
    pending_delay_complete: bool,
}

impl<S> AsyncTlsFragmentingWriter<S> {
    fn new(inner: S, options: TlsFragmentOptions) -> Self {
        Self {
            inner,
            planner: TlsFragmentPlanner::new(options),
            pending_plan: None,
            pending_segment: 0,
            pending_offset: 0,
            pending_delay: None,
            pending_delay_complete: false,
        }
    }

    fn queue_plan(&mut self, plan: TlsFragmentPlan) {
        if plan.is_empty() {
            return;
        }
        debug_assert!(self.pending_plan.is_none());
        self.pending_plan = Some(plan);
        self.pending_segment = 0;
        self.pending_offset = 0;
        self.pending_delay = None;
        self.pending_delay_complete = false;
    }

    fn clear_pending(&mut self) {
        self.pending_plan = None;
        self.pending_segment = 0;
        self.pending_offset = 0;
        self.pending_delay = None;
        self.pending_delay_complete = false;
    }
}

impl<S: AsyncWrite + Unpin> AsyncTlsFragmentingWriter<S> {
    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        loop {
            let Some(plan) = self.pending_plan.as_ref() else {
                return Poll::Ready(Ok(()));
            };
            let Some(segment) = plan.segments().get(self.pending_segment).copied() else {
                self.clear_pending();
                continue;
            };

            if !self.pending_delay_complete {
                if segment.delay_before_ms == 0 {
                    self.pending_delay_complete = true;
                } else {
                    if self.pending_delay.is_none() {
                        self.pending_delay = Some(Box::pin(time::sleep(Duration::from_millis(
                            segment.delay_before_ms,
                        ))));
                    }
                    let delay = self
                        .pending_delay
                        .as_mut()
                        .expect("a delayed TLS fragment segment has a Tokio deadline");
                    if delay.as_mut().poll(cx).is_pending() {
                        return Poll::Pending;
                    }
                    self.pending_delay = None;
                    self.pending_delay_complete = true;
                }
            }

            let pending_offset = self.pending_offset;
            let write_result = {
                let Self {
                    inner,
                    pending_plan,
                    ..
                } = self;
                let bytes = &pending_plan
                    .as_ref()
                    .expect("pending TLS fragment plan remains present while writing")
                    .bytes()[pending_offset..segment.end];
                Pin::new(inner).poll_write(cx, bytes)
            };
            match write_result {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "write tls-fragmented TCP underlay: wrote zero bytes",
                    )));
                }
                Poll::Ready(Ok(written)) => {
                    self.pending_offset += written;
                    if self.pending_offset == segment.end {
                        self.pending_segment += 1;
                        self.pending_delay = None;
                        self.pending_delay_complete = false;
                    }
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_finish_output(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }

        let incomplete = self.planner.finish_incomplete();
        self.queue_plan(incomplete);
        self.poll_flush_pending(cx)
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
        if self.planner.is_passthrough() {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }

        let plan = self
            .planner
            .push(buf)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
        self.queue_plan(plan);

        match self.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Ready(Ok(buf.len())),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.poll_finish_output(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.poll_finish_output(cx) {
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
