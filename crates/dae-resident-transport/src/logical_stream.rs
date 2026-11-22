use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

pub const VLESS_WRAPPER_LOGICAL_STREAM_BUFFER_BYTES: usize = 64 * 1024;

/// A bounded byte-stream facade driven by a transport-specific framing task.
///
/// The transport task owns the other side of the duplex stream.  Dropping the
/// facade aborts the task, so a failed handshake or cancelled relay cannot
/// leave a wrapper owner detached from the connection lifecycle.
pub struct SpawnedLogicalStream {
    stream: DuplexStream,
    task: tokio::task::JoinHandle<()>,
    terminal_error: Arc<OnceLock<String>>,
}

impl SpawnedLogicalStream {
    pub fn spawn<F, Fut>(driver: F) -> Self
    where
        F: FnOnce(DuplexStream) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let (stream, transport_side) = tokio::io::duplex(VLESS_WRAPPER_LOGICAL_STREAM_BUFFER_BYTES);
        let terminal_error = Arc::new(OnceLock::new());
        let task_error = Arc::clone(&terminal_error);
        let task = tokio::spawn(async move {
            if let Err(error) = driver(transport_side).await {
                let _ = task_error.set(error);
            }
        });
        Self {
            stream,
            task,
            terminal_error,
        }
    }

    fn terminal_io_error(&self) -> Option<io::Error> {
        self.terminal_error.get().cloned().map(io::Error::other)
    }
}

impl AsyncRead for SpawnedLogicalStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        target: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = target.filled().len();
        match Pin::new(&mut self.stream).poll_read(cx, target) {
            Poll::Ready(Ok(())) if target.filled().len() == before => {
                if let Some(error) = self.terminal_io_error() {
                    Poll::Ready(Err(error))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            result => result,
        }
    }
}

impl AsyncWrite for SpawnedLogicalStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(error) = self.terminal_io_error() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.stream).poll_write(cx, payload)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.terminal_io_error() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl Drop for SpawnedLogicalStream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests;
