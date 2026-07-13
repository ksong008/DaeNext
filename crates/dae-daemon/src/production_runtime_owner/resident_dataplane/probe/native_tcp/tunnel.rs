use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::task::JoinHandle;

pub(super) trait NativeTcpTunnel: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> NativeTcpTunnel for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

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
    task: JoinHandle<()>,
}

impl SpawnedNativeTcpTunnel {
    pub(super) fn new(stream: DuplexStream, task: JoinHandle<()>) -> Self {
        Self { stream, task }
    }
}

impl Drop for SpawnedNativeTcpTunnel {
    fn drop(&mut self) {
        self.task.abort();
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
