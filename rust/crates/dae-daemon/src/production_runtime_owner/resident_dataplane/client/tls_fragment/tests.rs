use super::*;
use std::task::{RawWaker, RawWakerVTable, Waker};

struct PendingAfterPartialWrite {
    bytes: Vec<u8>,
    state: PartialWriteState,
}

enum PartialWriteState {
    PartialReady,
    PendingOnce,
    Ready,
}

impl AsyncRead for PendingAfterPartialWrite {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for PendingAfterPartialWrite {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.state {
            PartialWriteState::PartialReady => {
                let consumed = 3.min(buf.len());
                self.bytes.extend_from_slice(&buf[..consumed]);
                self.state = PartialWriteState::PendingOnce;
                Poll::Ready(Ok(consumed))
            }
            PartialWriteState::PendingOnce => {
                self.state = PartialWriteState::Ready;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            PartialWriteState::Ready => {
                self.bytes.extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn noop_waker() -> Waker {
    unsafe fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    unsafe fn wake(_: *const ()) {}
    unsafe fn wake_by_ref(_: *const ()) {}
    unsafe fn drop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
}

#[test]
fn async_tls_fragmenting_writer_does_not_replay_consumed_pending_write() {
    let options = TlsFragmentOptions::from_ranges("8-8", "0-0").unwrap();
    let writer = PendingAfterPartialWrite {
        bytes: Vec::new(),
        state: PartialWriteState::PartialReady,
    };
    let mut stream = AsyncTlsFragmentingWriter::new(writer, options);
    let mut input = vec![
        dae_outbound::shared_transport::TLS_HANDSHAKE_CONTENT_TYPE,
        0x03,
        0x03,
        0,
        20,
    ];
    input.extend(0_u8..20);
    let expected = fragment_tls_write(&input, &stream.options).unwrap().bytes;

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let written = Pin::new(&mut stream)
        .poll_write(&mut cx, &input)
        .map(|result| result.unwrap());

    assert_eq!(written, Poll::Ready(input.len()));
    assert!(stream.pending_offset > 0);
    assert!(
        Pin::new(&mut stream)
            .poll_flush(&mut cx)
            .map(Result::unwrap)
            .is_ready()
    );
    assert_eq!(stream.inner.bytes, expected);
}
