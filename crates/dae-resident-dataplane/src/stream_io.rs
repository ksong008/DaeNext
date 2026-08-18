use std::fmt;
use std::io::IoSlice;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::time;

const HTTP_HEAD_READ_BUFFER_BYTES: usize = 512;

#[derive(Clone, Copy, Debug)]
pub(crate) struct HttpHeadReadOptions {
    pub(crate) max_bytes: usize,
    pub(crate) read_timeout: Option<Duration>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct HttpHeadRead {
    pub(crate) head: Vec<u8>,
    pub(crate) leftover: Vec<u8>,
}

#[derive(Debug)]
pub(crate) enum HttpHeadReadError {
    Io(std::io::Error),
    Timeout,
    EarlyEof,
    TooLarge,
}

impl fmt::Display for HttpHeadReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Timeout => formatter.write_str("timeout"),
            Self::EarlyEof => formatter.write_str("early eof"),
            Self::TooLarge => formatter.write_str("response head too large"),
        }
    }
}

impl std::error::Error for HttpHeadReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Timeout | Self::EarlyEof | Self::TooLarge => None,
        }
    }
}

pub(crate) async fn read_http_head<S>(
    stream: &mut S,
    options: HttpHeadReadOptions,
) -> Result<HttpHeadRead, HttpHeadReadError>
where
    S: AsyncRead + Unpin,
{
    let mut response = Vec::new();
    let mut buffer = [0_u8; HTTP_HEAD_READ_BUFFER_BYTES];
    loop {
        let read = match options.read_timeout {
            Some(timeout) => time::timeout(timeout, stream.read(&mut buffer))
                .await
                .map_err(|_| HttpHeadReadError::Timeout)?,
            None => stream.read(&mut buffer).await,
        }
        .map_err(HttpHeadReadError::Io)?;
        if read == 0 {
            return Err(HttpHeadReadError::EarlyEof);
        }
        response.extend_from_slice(&buffer[..read]);
        if let Some(index) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            let head_end = index + 4;
            if head_end > options.max_bytes {
                return Err(HttpHeadReadError::TooLarge);
            }
            let leftover = response.split_off(head_end);
            return Ok(HttpHeadRead {
                head: response,
                leftover,
            });
        }
        if response.len() > options.max_bytes {
            return Err(HttpHeadReadError::TooLarge);
        }
    }
}

pub(crate) struct AsyncPrefixedStream<S> {
    prefix: CursorBytes,
    inner: S,
}

impl<S> AsyncPrefixedStream<S> {
    pub(crate) fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix: CursorBytes::new(prefix),
            inner,
        }
    }
}

impl<S> AsyncRead for AsyncPrefixedStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.prefix.drain_to_read_buf(buffer);
        if buffer.remaining() == 0 || !self.prefix.is_empty() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<S> AsyncWrite for AsyncPrefixedStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(context, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[derive(Debug, Default)]
pub(crate) struct CursorBytes {
    bytes: Vec<u8>,
    offset: usize,
}

impl CursorBytes {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.offset >= self.bytes.len()
    }

    pub(crate) fn drain_to_read_buf(&mut self, output: &mut ReadBuf<'_>) -> bool {
        if self.is_empty() || output.remaining() == 0 {
            return false;
        }
        let available = &self.bytes[self.offset..];
        let len = available.len().min(output.remaining());
        output.put_slice(&available[..len]);
        self.offset += len;
        if self.offset >= self.bytes.len() {
            self.bytes.clear();
            self.offset = 0;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    struct ChunkedReader {
        chunks: VecDeque<Vec<u8>>,
    }

    impl ChunkedReader {
        fn new(chunks: impl IntoIterator<Item = &'static [u8]>) -> Self {
            Self {
                chunks: chunks
                    .into_iter()
                    .map(<[u8]>::to_vec)
                    .collect::<VecDeque<_>>(),
            }
        }
    }

    impl AsyncRead for ChunkedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let Some(mut chunk) = self.chunks.pop_front() else {
                return Poll::Ready(Ok(()));
            };
            let read = chunk.len().min(buffer.remaining());
            buffer.put_slice(&chunk[..read]);
            if read < chunk.len() {
                chunk.drain(..read);
                self.chunks.push_front(chunk);
            }
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn http_head_terminator_can_span_one_to_four_reads() {
        let cases: [Vec<&'static [u8]>; 4] = [
            vec![b"HTTP/1.1 200 OK\r\n\r\nbody"],
            vec![b"HTTP/1.1 200 OK\r\n\r", b"\nbody"],
            vec![b"HTTP/1.1 200 OK\r\n", b"\r", b"\nbody"],
            vec![b"HTTP/1.1 200 OK\r", b"\n", b"\r", b"\nbody"],
        ];
        for chunks in cases {
            let mut reader = ChunkedReader::new(chunks);
            let result = read_http_head(
                &mut reader,
                HttpHeadReadOptions {
                    max_bytes: 1024,
                    read_timeout: None,
                },
            )
            .await
            .unwrap();
            assert_eq!(result.head, b"HTTP/1.1 200 OK\r\n\r\n");
            assert_eq!(result.leftover, b"body");
        }
    }

    #[tokio::test]
    async fn http_head_reports_eof_limit_and_timeout_separately() {
        let options = HttpHeadReadOptions {
            max_bytes: 4,
            read_timeout: None,
        };
        let mut incomplete = ChunkedReader::new([b"abc".as_slice()]);
        assert!(matches!(
            read_http_head(&mut incomplete, options).await,
            Err(HttpHeadReadError::EarlyEof)
        ));

        let mut oversized = ChunkedReader::new([b"abcde".as_slice()]);
        assert!(matches!(
            read_http_head(&mut oversized, options).await,
            Err(HttpHeadReadError::TooLarge)
        ));

        let (_writer, mut pending) = tokio::io::duplex(16);
        assert!(matches!(
            read_http_head(
                &mut pending,
                HttpHeadReadOptions {
                    max_bytes: 16,
                    read_timeout: Some(Duration::from_millis(10)),
                },
            )
            .await,
            Err(HttpHeadReadError::Timeout)
        ));
    }

    #[tokio::test]
    async fn prefixed_stream_drains_prefix_before_inner_with_small_buffers() {
        let mut stream = AsyncPrefixedStream::new(
            b"prefix".to_vec(),
            ChunkedReader::new([b"inner".as_slice()]),
        );
        let mut output = Vec::new();
        let mut buffer = [0_u8; 2];
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            if read == 0 {
                break;
            }
            output.extend_from_slice(&buffer[..read]);
        }
        assert_eq!(output, b"prefixinner");
    }

    #[derive(Default)]
    struct VectoredWriteState {
        calls: usize,
        bytes: Vec<u8>,
    }

    struct VectoredWriter {
        state: Arc<Mutex<VectoredWriteState>>,
    }

    impl AsyncWrite for VectoredWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.state.lock().unwrap().bytes.extend_from_slice(buffer);
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffers: &[IoSlice<'_>],
        ) -> Poll<std::io::Result<usize>> {
            let mut state = self.state.lock().unwrap();
            state.calls += 1;
            let mut written = 0;
            for buffer in buffers {
                state.bytes.extend_from_slice(buffer);
                written += buffer.len();
            }
            Poll::Ready(Ok(written))
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn prefixed_stream_forwards_vectored_write_capability() {
        let state = Arc::new(Mutex::new(VectoredWriteState::default()));
        let writer = VectoredWriter {
            state: Arc::clone(&state),
        };
        let mut stream = AsyncPrefixedStream::new(Vec::new(), writer);
        assert!(stream.is_write_vectored());
        let written = stream
            .write_vectored(&[IoSlice::new(b"header"), IoSlice::new(b"payload")])
            .await
            .unwrap();
        assert_eq!(written, 13);
        let state = state.lock().unwrap();
        assert_eq!(state.calls, 1);
        assert_eq!(state.bytes, b"headerpayload");
    }
}
