use super::*;
use dae_outbound::shared_transport::{TlsFragmentPlan, TlsFragmentPlanner};
use std::future::Future;
use std::time::Duration;

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
