use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
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
    terminal_error: Arc<Mutex<Option<String>>>,
}

impl SpawnedLogicalStream {
    pub fn spawn<F, Fut>(driver: F) -> Self
    where
        F: FnOnce(DuplexStream) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let (stream, transport_side) = tokio::io::duplex(VLESS_WRAPPER_LOGICAL_STREAM_BUFFER_BYTES);
        let terminal_error = Arc::new(Mutex::new(None));
        let task_error = Arc::clone(&terminal_error);
        let task = tokio::spawn(async move {
            if let Err(error) = driver(transport_side).await
                && let Ok(mut terminal) = task_error.lock()
            {
                *terminal = Some(error);
            }
        });
        Self {
            stream,
            task,
            terminal_error,
        }
    }

    fn terminal_io_error(&self) -> Option<io::Error> {
        self.terminal_error
            .lock()
            .ok()
            .and_then(|terminal| terminal.clone())
            .map(io::Error::other)
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
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn spawned_logical_stream_is_bounded_and_duplex() {
        let mut stream = SpawnedLogicalStream::spawn(|mut transport| async move {
            let mut payload = [0_u8; 4];
            transport
                .read_exact(&mut payload)
                .await
                .map_err(|error| error.to_string())?;
            transport
                .write_all(&payload)
                .await
                .map_err(|error| error.to_string())?;
            Ok(())
        });
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
    }

    #[tokio::test]
    async fn spawned_logical_stream_surfaces_driver_failure() {
        let mut stream = SpawnedLogicalStream::spawn(|_transport| async move {
            Err("wrapper driver failed".to_owned())
        });
        tokio::task::yield_now().await;
        let mut byte = [0_u8; 1];
        let error = stream.read(&mut byte).await.unwrap_err();
        assert!(error.to_string().contains("wrapper driver failed"));
    }
}
