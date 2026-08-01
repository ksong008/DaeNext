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
