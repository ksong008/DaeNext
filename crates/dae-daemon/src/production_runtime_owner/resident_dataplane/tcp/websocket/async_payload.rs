use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::framing::WebSocketBinaryFrameDecoder;

#[derive(Default)]
pub(crate) struct AsyncWebSocketPayloadState {
    decoder: WebSocketBinaryFrameDecoder,
    pending: CursorByteBuffer,
    control: AsyncWebSocketControlWriter,
}

pub(crate) struct AsyncWebSocketPayloadReader<'a, 'b, R> {
    client: &'a mut R,
    state: &'b mut AsyncWebSocketPayloadState,
}

impl<'a, 'b, R> AsyncWebSocketPayloadReader<'a, 'b, R>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn new(client: &'a mut R, state: &'b mut AsyncWebSocketPayloadState) -> Self {
        Self { client, state }
    }
}

impl<R> AsyncRead for AsyncWebSocketPayloadReader<'_, '_, R>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let client = &mut *this.client;
        let state = &mut *this.state;

        loop {
            match state.control.poll_flush(&mut *client, cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
            if state.pending.drain_to_read_buf(out) || out.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if state.decoder.is_closed() {
                return Poll::Ready(Ok(()));
            }

            let mut buf = [0_u8; 8192];
            let mut read_buf = ReadBuf::new(&mut buf);
            match Pin::new(&mut *client).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let read = read_buf.filled();
                    if read.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    let frames = state.decoder.push(read).map_err(std::io::Error::other)?;
                    for frame in frames {
                        state.pending.extend_from_slice(&frame);
                    }
                    state.control.queue_from(&mut state.decoder);
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[derive(Default)]
pub(crate) struct AsyncWebSocketControlWriter {
    pending: CursorByteBuffer,
    needs_flush: bool,
}

impl AsyncWebSocketControlWriter {
    pub(crate) fn queue_from(&mut self, decoder: &mut WebSocketBinaryFrameDecoder) {
        for response in decoder.take_control_responses() {
            self.pending.extend_from_slice(&response);
            self.needs_flush = true;
        }
    }

    pub(crate) fn poll_flush<R>(
        &mut self,
        client: &mut R,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>>
    where
        R: AsyncWrite + Unpin,
    {
        while !self.pending.as_slice().is_empty() {
            match Pin::new(&mut *client).poll_write(cx, self.pending.as_slice()) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        ErrorKind::WriteZero,
                        "write websocket control response returned zero bytes",
                    )));
                }
                Poll::Ready(Ok(written)) => self.pending.consume(written),
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if self.needs_flush {
            match Pin::new(client).poll_flush(cx) {
                Poll::Ready(Ok(())) => self.needs_flush = false,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct CursorByteBuffer {
    bytes: Vec<u8>,
    offset: usize,
}

impl CursorByteBuffer {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[self.offset..]
    }

    fn extend_from_slice(&mut self, data: &[u8]) {
        self.compact_if_worthwhile();
        self.bytes.extend_from_slice(data);
    }

    fn consume(&mut self, len: usize) {
        self.offset += len;
        if self.offset >= self.bytes.len() {
            self.bytes.clear();
            self.offset = 0;
        } else {
            self.compact_if_worthwhile();
        }
    }

    fn drain_to_read_buf(&mut self, out: &mut ReadBuf<'_>) -> bool {
        let copy_len = self.as_slice().len().min(out.remaining());
        if copy_len == 0 {
            return false;
        }
        out.put_slice(&self.as_slice()[..copy_len]);
        self.consume(copy_len);
        true
    }

    fn compact_if_worthwhile(&mut self) {
        if self.offset == 0 {
            return;
        }
        if self.offset >= self.bytes.len() {
            self.bytes.clear();
            self.offset = 0;
            return;
        }
        if self.offset >= 8192 && self.offset * 2 >= self.bytes.len() {
            self.bytes.drain(..self.offset);
            self.offset = 0;
        }
    }
}
