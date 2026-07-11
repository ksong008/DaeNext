use super::*;
use dae_outbound::shared_transport::fragment_tls_write;
use std::task::{RawWaker, RawWakerVTable, Waker};
use std::time::Duration;

#[derive(Default)]
struct ReadyWriter {
    bytes: Vec<u8>,
}

impl AsyncWrite for ReadyWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.bytes.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

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
    let expected = fragment_tls_write(&input, stream.planner.options())
        .unwrap()
        .bytes;

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

#[test]
fn async_tls_fragmenting_writer_assembles_a_record_split_across_writes() {
    let options = TlsFragmentOptions::from_ranges("8-8", "0-0").unwrap();
    let mut stream = AsyncTlsFragmentingWriter::new(ReadyWriter::default(), options);
    let mut input = vec![
        dae_outbound::shared_transport::TLS_HANDSHAKE_CONTENT_TYPE,
        0x03,
        0x03,
        0,
        20,
    ];
    input.extend(0_u8..20);
    let expected = fragment_tls_write(&input, stream.planner.options())
        .unwrap()
        .bytes;
    let split_at = dae_outbound::shared_transport::TLS_RECORD_HEADER_LEN + 3;

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert_eq!(
        Pin::new(&mut stream)
            .poll_write(&mut cx, &input[..split_at])
            .map(Result::unwrap),
        Poll::Ready(split_at)
    );
    assert!(stream.inner.bytes.is_empty());
    assert_eq!(
        Pin::new(&mut stream)
            .poll_write(&mut cx, &input[split_at..])
            .map(Result::unwrap),
        Poll::Ready(input.len() - split_at)
    );
    assert_eq!(stream.inner.bytes, expected);
}

#[tokio::test]
async fn async_tls_fragmenting_writer_waits_between_fragments_without_final_delay() {
    let options = TlsFragmentOptions::from_ranges("8-8", "40-40").unwrap();
    let mut stream = AsyncTlsFragmentingWriter::new(ReadyWriter::default(), options);
    let mut input = vec![
        dae_outbound::shared_transport::TLS_HANDSHAKE_CONTENT_TYPE,
        0x03,
        0x03,
        0,
        20,
    ];
    input.extend(0_u8..20);

    tokio::io::AsyncWriteExt::write_all(&mut stream, &input)
        .await
        .unwrap();
    assert_eq!(
        stream.inner.bytes.len(),
        dae_outbound::shared_transport::TLS_RECORD_HEADER_LEN + 8
    );

    assert!(
        tokio::time::timeout(
            Duration::from_millis(5),
            tokio::io::AsyncWriteExt::flush(&mut stream)
        )
        .await
        .is_err()
    );
    tokio::time::timeout(
        Duration::from_millis(250),
        tokio::io::AsyncWriteExt::flush(&mut stream),
    )
    .await
    .expect("fragment intervals should complete within the configured bound")
    .unwrap();

    tokio::time::timeout(
        Duration::from_millis(5),
        tokio::io::AsyncWriteExt::flush(&mut stream),
    )
    .await
    .expect("the final fragment must not leave a trailing interval")
    .unwrap();

    let expected = fragment_tls_write(&input, stream.planner.options())
        .unwrap()
        .bytes;
    assert_eq!(stream.inner.bytes, expected);
}

#[tokio::test]
async fn async_tls_fragmenting_writer_flushes_incomplete_input_without_loss() {
    let options = TlsFragmentOptions::from_ranges("8-8", "0-0").unwrap();
    let mut stream = AsyncTlsFragmentingWriter::new(ReadyWriter::default(), options);
    let mut input = vec![
        dae_outbound::shared_transport::TLS_HANDSHAKE_CONTENT_TYPE,
        0x03,
        0x03,
        0,
        20,
    ];
    input.extend(0_u8..20);
    let split_at = dae_outbound::shared_transport::TLS_RECORD_HEADER_LEN + 3;

    tokio::io::AsyncWriteExt::write_all(&mut stream, &input[..split_at])
        .await
        .unwrap();
    assert!(stream.inner.bytes.is_empty());
    tokio::io::AsyncWriteExt::flush(&mut stream).await.unwrap();
    assert_eq!(stream.inner.bytes, input[..split_at]);

    tokio::io::AsyncWriteExt::write_all(&mut stream, &input[split_at..])
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::shutdown(&mut stream)
        .await
        .unwrap();
    assert_eq!(stream.inner.bytes, input);
}

#[tokio::test]
async fn async_tls_fragmenting_writer_preserves_multiple_record_order_and_boundaries() {
    let options = TlsFragmentOptions::from_ranges("8-8", "0-0").unwrap();
    let mut stream = AsyncTlsFragmentingWriter::new(ReadyWriter::default(), options.clone());
    let mut first = vec![
        dae_outbound::shared_transport::TLS_HANDSHAKE_CONTENT_TYPE,
        0x03,
        0x03,
        0,
        20,
    ];
    first.extend(0_u8..20);
    let mut second = vec![
        dae_outbound::shared_transport::TLS_HANDSHAKE_CONTENT_TYPE,
        0x03,
        0x03,
        0,
        9,
    ];
    second.extend(20_u8..29);
    let application_data = [23, 0x03, 0x03, 0, 3, 1, 2, 3];
    let mut input = first.clone();
    input.extend_from_slice(&second);
    input.extend_from_slice(&application_data);

    tokio::io::AsyncWriteExt::write_all(&mut stream, &input)
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::flush(&mut stream).await.unwrap();

    let mut expected = fragment_tls_write(&first, &options).unwrap().bytes;
    expected.extend(fragment_tls_write(&second, &options).unwrap().bytes);
    expected.extend_from_slice(&application_data);
    assert_eq!(stream.inner.bytes, expected);
    assert!(stream.planner.is_passthrough());
    assert!(stream.pending_plan.is_none());

    let later_application_data = b"later encrypted application data";
    tokio::io::AsyncWriteExt::write_all(&mut stream, later_application_data)
        .await
        .unwrap();
    assert!(stream.pending_plan.is_none());
    assert!(stream.inner.bytes.ends_with(later_application_data));
}
