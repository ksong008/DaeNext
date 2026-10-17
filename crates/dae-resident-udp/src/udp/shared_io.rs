//! A transport is promoted only when DNS needs an independent send operation.
//! The shared lock protects one poll, never an await or a whole exchange.
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) enum UdpSharedIo<T> {
    Exclusive(Option<T>),
    Shared(Arc<Mutex<T>>),
}

impl<T> From<T> for UdpSharedIo<T> {
    fn from(io: T) -> Self {
        Self::Exclusive(Some(io))
    }
}

impl<T> UdpSharedIo<T> {
    pub(super) fn share(&mut self) -> Result<Self, String> {
        if let Self::Exclusive(io) = self {
            let owned = io
                .take()
                .ok_or_else(|| "UDP transport promotion lost its owner".to_owned())?;
            *self = Self::Shared(Arc::new(Mutex::new(owned)));
        }
        match self {
            Self::Shared(io) => Ok(Self::Shared(Arc::clone(io))),
            Self::Exclusive(_) => Err("UDP transport promotion failed".to_owned()),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn inspect<R>(&self, f: impl FnOnce(&T) -> R) -> Result<R, String> {
        match self {
            Self::Exclusive(Some(io)) => Ok(f(io)),
            Self::Shared(io) => io
                .lock()
                .map(|io| f(&io))
                .map_err(|_| "UDP transport lock poisoned".to_owned()),
            Self::Exclusive(None) => Err("UDP transport has no owner".to_owned()),
        }
    }

    fn poll_with<R>(
        &mut self,
        f: impl FnOnce(&mut T) -> Poll<io::Result<R>>,
    ) -> Poll<io::Result<R>> {
        match self {
            Self::Exclusive(Some(io)) => f(io),
            Self::Exclusive(None) => {
                Poll::Ready(Err(io::Error::other("UDP transport has no owner")))
            }
            Self::Shared(io) => match io.lock() {
                Ok(mut io) => f(&mut io),
                Err(_) => Poll::Ready(Err(io::Error::other("UDP transport lock poisoned"))),
            },
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for UdpSharedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_with(|io| Pin::new(io).poll_read(cx, buf))
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for UdpSharedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_with(|io| Pin::new(io).poll_write(cx, buf))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_with(|io| Pin::new(io).poll_flush(cx))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_with(|io| Pin::new(io).poll_shutdown(cx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProxyDnsUdpSend;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn partial_stream_send_allows_receiving_but_requires_session_reset_on_cancel() {
        let (client, mut server) = tokio::io::duplex(4);
        let mut reader = UdpSharedIo::from(client);
        let mut send = ProxyDnsUdpSend::stream(reader.share().unwrap(), vec![7; 32], false);
        std::future::poll_fn(|cx| {
            assert!(send.future.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let mut prefix = [0; 4];
        server.read_exact(&mut prefix).await.unwrap();
        assert_eq!(
            prefix, [7; 4],
            "the writer really emitted only a frame prefix"
        );
        server.write_all(&[1, 2, 3, 4]).await.unwrap();
        let mut response = [0; 4];
        reader.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [1, 2, 3, 4]);
        assert!(send.reset_on_cancel);
        drop(send);
    }
}
