use super::*;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;

enum ScriptedRead {
    Data(Bytes),
    Pending,
    Error(io::ErrorKind),
    Eof,
}

struct ScriptedReader {
    reads: VecDeque<ScriptedRead>,
}

impl ScriptedReader {
    fn new(reads: impl IntoIterator<Item = ScriptedRead>) -> Self {
        Self {
            reads: reads.into_iter().collect(),
        }
    }
}

impl AsyncRead for ScriptedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(read) = self.reads.pop_front() else {
            return Poll::Ready(Ok(()));
        };
        match read {
            ScriptedRead::Data(mut data) => {
                let take = data.len().min(buffer.remaining());
                buffer.put_slice(&data.split_to(take));
                if !data.is_empty() {
                    self.reads.push_front(ScriptedRead::Data(data));
                }
                Poll::Ready(Ok(()))
            }
            ScriptedRead::Pending => {
                self.reads.push_front(ScriptedRead::Pending);
                Poll::Pending
            }
            ScriptedRead::Error(kind) => Poll::Ready(Err(io::Error::from(kind))),
            ScriptedRead::Eof => Poll::Ready(Ok(())),
        }
    }
}

#[tokio::test]
async fn packet_up_reader_coalesces_only_immediately_ready_data() {
    let reader = ScriptedReader::new([
        ScriptedRead::Data(Bytes::from_static(b"alpha")),
        ScriptedRead::Data(Bytes::from_static(b"-beta")),
        ScriptedRead::Pending,
    ]);
    let mut reader = XhttpUploadChunkReader::new(reader);

    let chunk = reader.read_chunk(1024).await.unwrap().unwrap();

    assert_eq!(chunk, Bytes::from_static(b"alpha-beta"));
}

#[tokio::test]
async fn packet_up_reader_keeps_overflow_for_the_next_post() {
    let payload = Bytes::from(vec![0x5a; XHTTP_UPLOAD_READ_CHUNK + 97]);
    let reader = ScriptedReader::new([ScriptedRead::Data(payload), ScriptedRead::Eof]);
    let mut reader = XhttpUploadChunkReader::new(reader);

    let first = reader.read_chunk(1024).await.unwrap().unwrap();
    let second = reader.read_chunk(1024).await.unwrap().unwrap();

    assert_eq!(first.len(), 1024);
    assert_eq!(second.len(), 1024);
    assert!(first.iter().chain(second.iter()).all(|byte| *byte == 0x5a));
}

#[tokio::test]
async fn packet_up_reader_delivers_buffer_before_ready_error() {
    let reader = ScriptedReader::new([
        ScriptedRead::Data(Bytes::from_static(b"payload")),
        ScriptedRead::Error(io::ErrorKind::ConnectionReset),
    ]);
    let mut reader = XhttpUploadChunkReader::new(reader);

    let chunk = reader.read_chunk(1024).await.unwrap().unwrap();
    let error = reader.read_chunk(1024).await.unwrap_err();

    assert_eq!(chunk, Bytes::from_static(b"payload"));
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
}

#[tokio::test]
async fn stream_reader_preserves_one_read_per_chunk() {
    let mut reader = ScriptedReader::new([
        ScriptedRead::Data(Bytes::from_static(b"first")),
        ScriptedRead::Data(Bytes::from_static(b"second")),
        ScriptedRead::Eof,
    ]);
    let mut buffer = BytesMut::with_capacity(XHTTP_UPLOAD_READ_CHUNK);

    let first = read_xhttp_stream_upload_chunk(&mut reader, &mut buffer)
        .await
        .unwrap()
        .unwrap();
    let second = read_xhttp_stream_upload_chunk(&mut reader, &mut buffer)
        .await
        .unwrap()
        .unwrap();
    let eof = read_xhttp_stream_upload_chunk(&mut reader, &mut buffer)
        .await
        .unwrap();

    assert_eq!(first, Bytes::from_static(b"first"));
    assert_eq!(second, Bytes::from_static(b"second"));
    assert!(eof.is_none());
}

#[tokio::test]
async fn h3_download_flushes_before_waiting_for_the_next_response() {
    let (sink, mut peer) = tokio::io::duplex(64);
    let mut writer = BufWriter::with_capacity(XHTTP_H3_DOWNLOAD_WRITE_BUFFER, sink);
    writer.write_all(b"request").await.unwrap();
    let (send, receive) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let mut request = [0; 7];
        peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");
        send.send(Bytes::from_static(b"response")).unwrap();
    });
    let response = time::timeout(
        Duration::from_secs(1),
        read_download_flushing_pending(async { Ok(Some(receive.await.unwrap())) }, &mut writer),
    )
    .await
    .expect("buffered data must reach the peer before waiting for its response")
    .unwrap();
    assert_eq!(response, Some(Bytes::from_static(b"response")));
    peer.await.unwrap();
}

#[tokio::test]
async fn h3_download_preserves_buffered_bytes_across_backpressure_and_terminal_reads() {
    for fail in [false, true] {
        let (sink, mut peer) = tokio::io::duplex(97);
        let expected = (0..100_003).map(|n| (n % 251) as u8).collect::<Vec<_>>();
        let output = tokio::spawn(async move {
            let mut received = Vec::new();
            peer.read_to_end(&mut received).await.unwrap();
            received
        });
        let mut writer = BufWriter::with_capacity(XHTTP_H3_DOWNLOAD_WRITE_BUFFER, sink);
        for chunk in expected.chunks(1408) {
            let ready = read_download_flushing_pending(
                std::future::ready(Ok(Some(Bytes::copy_from_slice(chunk)))),
                &mut writer,
            )
            .await
            .unwrap()
            .unwrap();
            writer.write_all(&ready).await.unwrap();
        }
        let terminal = if fail {
            Err("remote reset".to_owned())
        } else {
            Ok(None)
        };
        let result =
            read_download_flushing_pending(std::future::ready(terminal.clone()), &mut writer).await;
        assert_eq!(result, terminal);
        // Drop without shutdown: the terminal read must already have flushed.
        drop(writer);
        assert_eq!(output.await.unwrap(), expected);
    }
}
