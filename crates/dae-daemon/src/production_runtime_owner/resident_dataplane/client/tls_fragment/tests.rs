use super::*;
use dae_outbound::shared_transport::fragment_tls_write;
use std::task::{RawWaker, RawWakerVTable, Waker};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
async fn tls_record_bounded_reader_does_not_consume_raw_tail() {
    let (mut writer, reader) = tokio::io::duplex(64);
    let record = [23, 3, 3, 0, 4, 0xaa, 0xbb, 0xcc, 0xdd];
    let raw_tail = b"raw-direct-tail";
    writer.write_all(&record).await.unwrap();
    writer.write_all(raw_tail).await.unwrap();

    let mut reader = TlsRecordBoundedReader::new(reader);
    let mut output = [0_u8; 32];

    let header_read = reader.read(&mut output).await.unwrap();
    assert_eq!(header_read, TLS_RECORD_HEADER_BYTES);
    assert_eq!(&output[..header_read], &record[..TLS_RECORD_HEADER_BYTES]);
    assert!(!reader.at_record_boundary());

    let payload_read = reader.read(&mut output[header_read..]).await.unwrap();
    assert_eq!(payload_read, record.len() - TLS_RECORD_HEADER_BYTES);
    assert_eq!(
        &output[header_read..header_read + payload_read],
        &record[TLS_RECORD_HEADER_BYTES..]
    );
    assert!(reader.at_record_boundary());
    reader.enable_record_handoff();
    assert!(reader.record_handoff_ready());

    let mut blocked = [0_u8; 32];
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    for _ in 0..3 {
        let mut blocked_read = ReadBuf::new(&mut blocked);
        assert!(
            Pin::new(&mut reader)
                .poll_read(&mut cx, &mut blocked_read)
                .is_pending()
        );
        assert!(blocked_read.filled().is_empty());
        assert!(reader.record_handoff_ready());
    }

    let mut recovered_tail = vec![0_u8; raw_tail.len()];
    reader
        .inner_mut()
        .read_exact(&mut recovered_tail)
        .await
        .unwrap();
    assert_eq!(recovered_tail, raw_tail);
}

#[tokio::test]
async fn tls_record_handoff_gate_requires_explicit_release_for_each_record() {
    let (mut writer, reader) = tokio::io::duplex(128);
    let first = [23, 3, 3, 0, 3, 0xaa, 0xbb, 0xcc];
    let second = [23, 3, 3, 0, 2, 0xdd, 0xee];
    writer.write_all(&first).await.unwrap();
    writer.write_all(&second).await.unwrap();

    let mut reader = TlsRecordBoundedReader::new(reader);
    reader.enable_record_handoff();
    assert!(reader.record_handoff_ready());

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    for _ in 0..3 {
        let mut output = [0_u8; 32];
        let mut blocked_read = ReadBuf::new(&mut output);
        assert!(
            Pin::new(&mut reader)
                .poll_read(&mut cx, &mut blocked_read)
                .is_pending()
        );
        assert!(blocked_read.filled().is_empty());
    }

    assert!(reader.take_record_handoff());
    assert!(!reader.take_record_handoff());
    let mut first_output = [0_u8; 8];
    reader.read_exact(&mut first_output).await.unwrap();
    assert_eq!(first_output, first);
    assert!(reader.record_handoff_ready());

    let mut blocked_output = [0_u8; 32];
    let mut blocked_read = ReadBuf::new(&mut blocked_output);
    assert!(
        Pin::new(&mut reader)
            .poll_read(&mut cx, &mut blocked_read)
            .is_pending()
    );
    assert!(blocked_read.filled().is_empty());

    assert!(reader.take_record_handoff());
    assert!(!reader.take_record_handoff());
    let mut second_output = [0_u8; 7];
    reader.read_exact(&mut second_output).await.unwrap();
    assert_eq!(second_output, second);
    assert!(reader.record_handoff_ready());
}

#[tokio::test]
async fn tls_record_reader_without_tcp_handoff_gate_allows_xudp_records() {
    let (mut writer, reader) = tokio::io::duplex(128);
    let first = [23, 3, 3, 0, 3, 0xaa, 0xbb, 0xcc];
    let second = [23, 3, 3, 0, 2, 0xdd, 0xee];
    writer.write_all(&first).await.unwrap();
    writer.write_all(&second).await.unwrap();

    let mut reader = TlsRecordBoundedReader::new(reader);
    let mut output = [0_u8; 15];
    reader.read_exact(&mut output).await.unwrap();

    assert_eq!(&output[..first.len()], first);
    assert_eq!(&output[first.len()..], second);
    assert!(reader.at_record_boundary());
    assert!(!reader.record_handoff_ready());
}

#[tokio::test]
async fn tls_record_bounded_reader_tracks_partial_header_and_payload() {
    let (mut writer, reader) = tokio::io::duplex(64);
    let record = [23, 3, 3, 0, 5, 1, 2, 3, 4, 5];
    writer.write_all(&record).await.unwrap();

    let mut reader = TlsRecordBoundedReader::new(reader);
    let mut output = [0_u8; 10];

    assert_eq!(reader.read(&mut output[..2]).await.unwrap(), 2);
    assert!(!reader.at_record_boundary());
    assert_eq!(reader.read(&mut output[2..5]).await.unwrap(), 3);
    assert!(!reader.at_record_boundary());
    assert_eq!(reader.read(&mut output[5..7]).await.unwrap(), 2);
    assert!(!reader.at_record_boundary());
    assert_eq!(reader.read(&mut output[7..]).await.unwrap(), 3);
    assert!(reader.at_record_boundary());
    assert_eq!(output, record);
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
