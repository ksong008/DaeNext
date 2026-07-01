use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::task::JoinHandle;

pub(super) trait NativeTcpTunnel: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> NativeTcpTunnel for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

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
