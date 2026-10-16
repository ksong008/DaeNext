use super::*;

/// Lazy, pooled read-ahead storage for framed streams. Large reads bypass it.
pub struct PooledReader<R> {
    inner: R,
    buffer: PooledBuffer,
    pos: usize,
    end: usize,
    capacity: usize,
}

impl<R> PooledReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buffer: PooledBuffer::default(),
            pos: 0,
            end: 0,
            capacity: 16 * 1024,
        }
    }
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }
    pub fn buffer(&self) -> &[u8] {
        &self.buffer[self.pos..self.end]
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PooledReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.pos == this.end {
            if out.remaining() >= this.capacity {
                return Pin::new(&mut this.inner).poll_read(cx, out);
            }
            this.buffer.resize(this.capacity, 0);
            let mut read = ReadBuf::new(&mut this.buffer);
            std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
            this.end = read.filled().len();
            this.pos = 0;
        }
        let len = out.remaining().min(this.end - this.pos);
        out.put_slice(&this.buffer[this.pos..this.pos + len]);
        this.pos += len;
        Poll::Ready(Ok(()))
    }
}

impl<R: AsyncWrite + Unpin> AsyncWrite for PooledReader<R> {
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
