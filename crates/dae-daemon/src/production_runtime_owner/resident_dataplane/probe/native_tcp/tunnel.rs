use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::task::JoinHandle;
use tokio::time::{self, Sleep};

use super::super::super::{RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE, SharedResidentStopSignal};

pub(super) trait NativeTcpTunnel: AsyncRead + AsyncWrite + Unpin + Send {
    fn poll_cleanup(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

pub(super) fn boxed_native_tcp_tunnel<T>(stream: T) -> Box<dyn NativeTcpTunnel>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    Box::new(PlainNativeTcpTunnel { stream })
}

pub(super) async fn cleanup_native_tcp_tunnel(tunnel: &mut dyn NativeTcpTunnel) -> io::Result<()> {
    std::future::poll_fn(|cx| tunnel.poll_cleanup(cx)).await
}

struct PlainNativeTcpTunnel<T> {
    stream: T,
}

impl<T> NativeTcpTunnel for PlainNativeTcpTunnel<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn poll_cleanup(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl<T> AsyncRead for PlainNativeTcpTunnel<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for PlainNativeTcpTunnel<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

pub(super) struct PrefixedNativeTcpTunnel<T> {
    prefix: Vec<u8>,
    offset: usize,
    stream: T,
}

impl<T> PrefixedNativeTcpTunnel<T> {
    pub(super) fn new(prefix: Vec<u8>, stream: T) -> Self {
        Self {
            prefix,
            offset: 0,
            stream,
        }
    }
}

impl<T> AsyncRead for PrefixedNativeTcpTunnel<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.offset < self.prefix.len() && buf.remaining() > 0 {
            let available = &self.prefix[self.offset..];
            let len = available.len().min(buf.remaining());
            buf.put_slice(&available[..len]);
            self.offset += len;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for PrefixedNativeTcpTunnel<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

pub(super) struct SpawnedNativeTcpTunnel {
    stream: DuplexStream,
    task: Option<JoinHandle<()>>,
    stop: SharedResidentStopSignal,
    cleanup_grace: Duration,
    cleanup_deadline: Option<Pin<Box<Sleep>>>,
    abort_requested: bool,
}

impl SpawnedNativeTcpTunnel {
    pub(super) fn new(
        stream: DuplexStream,
        task: JoinHandle<()>,
        stop: SharedResidentStopSignal,
    ) -> Self {
        Self::with_cleanup_grace(stream, task, stop, RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
    }

    fn with_cleanup_grace(
        stream: DuplexStream,
        task: JoinHandle<()>,
        stop: SharedResidentStopSignal,
        cleanup_grace: Duration,
    ) -> Self {
        Self {
            stream,
            task: Some(task),
            stop,
            cleanup_grace,
            cleanup_deadline: None,
            abort_requested: false,
        }
    }

    fn poll_task_join(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let Some(task) = self.task.as_mut() else {
            return Poll::Ready(());
        };
        match Pin::new(task).poll(cx) {
            Poll::Ready(_) => {
                self.task = None;
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl NativeTcpTunnel for SpawnedNativeTcpTunnel {
    fn poll_cleanup(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stop.store(true, Ordering::Release);
        if self.cleanup_deadline.is_none() {
            self.cleanup_deadline = Some(Box::pin(time::sleep(self.cleanup_grace)));
        }
        let shutdown = Pin::new(&mut self.stream).poll_shutdown(cx);
        if self.poll_task_join(cx).is_ready() {
            return match shutdown {
                Poll::Ready(result) => Poll::Ready(result),
                Poll::Pending => Poll::Ready(Ok(())),
            };
        }

        let cleanup_expired = self
            .cleanup_deadline
            .as_mut()
            .is_some_and(|deadline| deadline.as_mut().poll(cx).is_ready());
        if cleanup_expired && !self.abort_requested {
            if let Some(task) = self.task.as_ref() {
                task.abort();
            }
            self.abort_requested = true;
        }
        if self.abort_requested && self.poll_task_join(cx).is_ready() {
            return Poll::Ready(match shutdown {
                Poll::Ready(result) => result,
                Poll::Pending => Ok(()),
            });
        }
        Poll::Pending
    }
}

impl Drop for SpawnedNativeTcpTunnel {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

impl AsyncRead for SpawnedNativeTcpTunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for SpawnedNativeTcpTunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::production_runtime_owner::resident_dataplane::ResidentStopSignal;

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn cleanup_requests_stop_and_joins_the_relay() {
        let (probe, _relay) = tokio::io::duplex(64);
        let stop = ResidentStopSignal::shared();
        let mut listener = stop.listener();
        let task = tokio::spawn(async move { listener.cancelled().await });
        let mut tunnel = SpawnedNativeTcpTunnel::with_cleanup_grace(
            probe,
            task,
            Arc::clone(&stop),
            Duration::from_millis(10),
        );
        tokio::time::sleep(Duration::from_millis(20)).await;

        cleanup_native_tcp_tunnel(&mut tunnel).await.unwrap();

        assert!(stop.load(Ordering::Acquire));
        assert!(tunnel.task.is_none());
        assert!(!tunnel.abort_requested);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cleanup_escalates_to_abort_and_awaits_cancellation() {
        let (probe, _relay) = tokio::io::duplex(64);
        let stop = ResidentStopSignal::shared();
        let task = tokio::spawn(std::future::pending::<()>());
        let mut tunnel = SpawnedNativeTcpTunnel::with_cleanup_grace(
            probe,
            task,
            stop,
            Duration::from_millis(10),
        );

        tokio::time::timeout(
            Duration::from_secs(1),
            cleanup_native_tcp_tunnel(&mut tunnel),
        )
        .await
        .expect("cleanup timeout")
        .unwrap();

        assert!(tunnel.task.is_none());
        assert!(tunnel.abort_requested);
    }
}
