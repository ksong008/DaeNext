use std::io::IoSlice;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::DNS_TCP_MESSAGE_READ_LIMIT;

const DNS_TCP_FRAME_READ_CHUNK_SIZE: usize = 32 * 1024;

#[derive(Default)]
pub(in crate::production_runtime_owner::resident_dataplane) struct DnsTcpFrameReader {
    buffered: BytesMut,
}

impl DnsTcpFrameReader {
    pub(in crate::production_runtime_owner::resident_dataplane) async fn read_frame<S>(
        &mut self,
        stream: &mut S,
    ) -> Result<Option<Vec<u8>>, String>
    where
        S: AsyncRead + Unpin,
    {
        loop {
            if self.buffered.len() >= 2 {
                let len = u16::from_be_bytes([self.buffered[0], self.buffered[1]]) as usize;
                if len == 0 {
                    return Err("DNS TCP frame has empty payload".to_owned());
                }
                if len > DNS_TCP_MESSAGE_READ_LIMIT {
                    return Err(format!("DNS TCP frame length {len} exceeds read limit"));
                }
                let frame_len = 2 + len;
                if self.buffered.len() >= frame_len {
                    let frame = self.buffered.split_to(frame_len);
                    return Ok(Some(frame[2..].to_vec()));
                }
            }

            let read_limit = if self.buffered.len() < 2 {
                DNS_TCP_FRAME_READ_CHUNK_SIZE
            } else {
                let len = u16::from_be_bytes([self.buffered[0], self.buffered[1]]) as usize;
                (2 + len).saturating_sub(self.buffered.len())
            };
            self.buffered.reserve(read_limit.max(1));
            let mut limited = stream.take(read_limit.max(1) as u64);
            let read = limited
                .read_buf(&mut self.buffered)
                .await
                .map_err(|err| format!("read DNS TCP frame: {err}"))?;
            if read != 0 {
                continue;
            }
            if self.buffered.is_empty() {
                return Ok(None);
            }
            return Err("read DNS TCP frame: early eof".to_owned());
        }
    }
}

#[cfg(test)]
pub(in crate::production_runtime_owner::resident_dataplane) async fn read_dns_tcp_payload_async<S>(
    stream: &mut S,
) -> Result<Option<Vec<u8>>, String>
where
    S: AsyncRead + Unpin,
{
    DnsTcpFrameReader::default().read_frame(stream).await
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn write_dns_tcp_payload_async<
    S,
>(
    stream: &mut S,
    payload: &[u8],
) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    let len = u16::try_from(payload.len())
        .map_err(|_| format!("DNS TCP response exceeds frame limit: {}", payload.len()))?;
    let length = len.to_be_bytes();
    if stream.is_write_vectored() {
        let slices = [IoSlice::new(&length), IoSlice::new(payload)];
        let written = stream
            .write_vectored(&slices)
            .await
            .map_err(|err| format!("write DNS TCP response frame: {err}"))?;
        if written == 0 {
            return Err("write DNS TCP response frame returned zero bytes".to_owned());
        }
        let frame_len = length.len().saturating_add(payload.len());
        if written < length.len() {
            stream
                .write_all(&length[written..])
                .await
                .map_err(|err| format!("write DNS TCP response length remainder: {err}"))?;
            stream
                .write_all(payload)
                .await
                .map_err(|err| format!("write DNS TCP response payload: {err}"))?;
        } else if written < frame_len {
            stream
                .write_all(&payload[written - length.len()..])
                .await
                .map_err(|err| format!("write DNS TCP response payload remainder: {err}"))?;
        }
    } else {
        let mut frame = Vec::with_capacity(length.len().saturating_add(payload.len()));
        frame.extend_from_slice(&length);
        frame.extend_from_slice(payload);
        stream
            .write_all(&frame)
            .await
            .map_err(|err| format!("write DNS TCP response frame: {err}"))?;
    }
    stream
        .flush()
        .await
        .map_err(|err| format!("flush DNS TCP response: {err}"))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::AsyncWriteExt;

    use super::*;

    enum WriteStep {
        Limit(usize),
        Pending,
        Zero,
        Error,
    }

    struct ScriptedWriter {
        steps: VecDeque<WriteStep>,
        written: Vec<u8>,
        is_vectored: bool,
        vectored_calls: usize,
        scalar_calls: usize,
        flushes: usize,
    }

    impl ScriptedWriter {
        fn new(steps: impl IntoIterator<Item = WriteStep>) -> Self {
            Self {
                steps: steps.into_iter().collect(),
                written: Vec::new(),
                is_vectored: true,
                vectored_calls: 0,
                scalar_calls: 0,
                flushes: 0,
            }
        }

        fn non_vectored() -> Self {
            Self {
                is_vectored: false,
                ..Self::new([])
            }
        }

        fn poll_scripted_write(
            &mut self,
            context: &mut Context<'_>,
            buffers: &[IoSlice<'_>],
        ) -> Poll<std::io::Result<usize>> {
            match self.steps.pop_front() {
                Some(WriteStep::Pending) => {
                    context.waker().wake_by_ref();
                    Poll::Pending
                }
                Some(WriteStep::Zero) => Poll::Ready(Ok(0)),
                Some(WriteStep::Error) => Poll::Ready(Err(std::io::Error::other("scripted"))),
                Some(WriteStep::Limit(limit)) => {
                    let mut remaining = limit;
                    let mut written = 0;
                    for buffer in buffers {
                        let take = remaining.min(buffer.len());
                        self.written.extend_from_slice(&buffer[..take]);
                        written += take;
                        remaining -= take;
                        if remaining == 0 {
                            break;
                        }
                    }
                    Poll::Ready(Ok(written))
                }
                None => {
                    let written = buffers.iter().map(|buffer| buffer.len()).sum();
                    for buffer in buffers {
                        self.written.extend_from_slice(buffer);
                    }
                    Poll::Ready(Ok(written))
                }
            }
        }
    }

    impl AsyncWrite for ScriptedWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.scalar_calls += 1;
            self.poll_scripted_write(context, &[IoSlice::new(buffer)])
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffers: &[IoSlice<'_>],
        ) -> Poll<std::io::Result<usize>> {
            self.vectored_calls += 1;
            self.poll_scripted_write(context, buffers)
        }

        fn is_write_vectored(&self) -> bool {
            self.is_vectored
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    async fn assert_scripted_write(steps: impl IntoIterator<Item = WriteStep>) -> ScriptedWriter {
        let payload = b"payload";
        let mut writer = ScriptedWriter::new(steps);
        write_dns_tcp_payload_async(&mut writer, payload)
            .await
            .unwrap();
        let mut expected = (payload.len() as u16).to_be_bytes().to_vec();
        expected.extend_from_slice(payload);
        assert_eq!(writer.written, expected);
        assert!(writer.vectored_calls >= 1);
        assert_eq!(writer.flushes, 1);
        writer
    }

    #[tokio::test]
    async fn tcp_wire_round_trips_dns_payload_with_length_prefix() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let request = b"dns-payload".to_vec();

        client
            .write_all(&(request.len() as u16).to_be_bytes())
            .await
            .unwrap();
        client.write_all(&request).await.unwrap();

        assert_eq!(
            read_dns_tcp_payload_async(&mut server).await.unwrap(),
            Some(request)
        );
    }

    #[tokio::test]
    async fn tcp_wire_writes_dns_payload_with_length_prefix() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let response = b"dns-response";

        write_dns_tcp_payload_async(&mut client, response)
            .await
            .unwrap();

        let mut framed = vec![0_u8; response.len() + 2];
        server.read_exact(&mut framed).await.unwrap();
        assert_eq!(
            u16::from_be_bytes([framed[0], framed[1]]) as usize,
            response.len()
        );
        assert_eq!(&framed[2..], response);
    }

    #[tokio::test]
    async fn tcp_frame_reader_retains_back_to_back_frames() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let first = b"first";
        let second = b"second";
        client
            .write_all(&(first.len() as u16).to_be_bytes())
            .await
            .unwrap();
        client.write_all(first).await.unwrap();
        client
            .write_all(&(second.len() as u16).to_be_bytes())
            .await
            .unwrap();
        client.write_all(second).await.unwrap();

        let mut reader = DnsTcpFrameReader::default();
        assert_eq!(
            reader.read_frame(&mut server).await.unwrap(),
            Some(first.to_vec())
        );
        assert_eq!(
            reader.read_frame(&mut server).await.unwrap(),
            Some(second.to_vec())
        );
    }

    #[tokio::test]
    async fn tcp_frame_reader_rejects_partial_payload_eof() {
        let (mut client, mut server) = tokio::io::duplex(32);
        client.write_all(&[0, 4, b'a', b'b']).await.unwrap();
        drop(client);

        let error = DnsTcpFrameReader::default()
            .read_frame(&mut server)
            .await
            .unwrap_err();
        assert!(error.contains("early eof"));
    }

    #[tokio::test]
    async fn tcp_frame_reader_rejects_partial_header_eof() {
        let (mut client, mut server) = tokio::io::duplex(8);
        client.write_all(&[0]).await.unwrap();
        drop(client);

        let error = DnsTcpFrameReader::default()
            .read_frame(&mut server)
            .await
            .unwrap_err();
        assert!(error.contains("early eof"));
    }

    #[tokio::test]
    async fn tcp_frame_reader_rejects_empty_payload() {
        let (mut client, mut server) = tokio::io::duplex(8);
        client.write_all(&[0, 0]).await.unwrap();

        let error = DnsTcpFrameReader::default()
            .read_frame(&mut server)
            .await
            .unwrap_err();
        assert!(error.contains("empty payload"));
    }

    #[tokio::test]
    async fn tcp_wire_partial_vectored_writes_preserve_exact_frame() {
        let partial_header = assert_scripted_write([WriteStep::Limit(1)]).await;
        assert_eq!(partial_header.vectored_calls, 1);
        assert_eq!(partial_header.scalar_calls, 2);

        let exact_header = assert_scripted_write([WriteStep::Limit(2)]).await;
        assert_eq!(exact_header.vectored_calls, 1);
        assert_eq!(exact_header.scalar_calls, 1);

        let partial_payload = assert_scripted_write([WriteStep::Limit(5)]).await;
        assert_eq!(partial_payload.vectored_calls, 1);
        assert_eq!(partial_payload.scalar_calls, 1);

        let pending = assert_scripted_write([WriteStep::Pending]).await;
        assert_eq!(pending.vectored_calls, 2);
        assert_eq!(pending.scalar_calls, 0);
    }

    #[tokio::test]
    async fn tcp_wire_coalesces_non_vectored_frame_into_one_write() {
        let payload = b"payload";
        let mut writer = ScriptedWriter::non_vectored();

        write_dns_tcp_payload_async(&mut writer, payload)
            .await
            .unwrap();

        let mut expected = (payload.len() as u16).to_be_bytes().to_vec();
        expected.extend_from_slice(payload);
        assert_eq!(writer.written, expected);
        assert_eq!(writer.vectored_calls, 0);
        assert_eq!(writer.scalar_calls, 1);
        assert_eq!(writer.flushes, 1);
    }

    #[tokio::test]
    async fn tcp_wire_rejects_zero_vectored_write() {
        let mut writer = ScriptedWriter::new([WriteStep::Zero]);
        let error = write_dns_tcp_payload_async(&mut writer, b"payload")
            .await
            .unwrap_err();
        assert!(error.contains("zero bytes"));
        assert_eq!(writer.flushes, 0);
    }

    #[tokio::test]
    async fn tcp_wire_propagates_vectored_write_error() {
        let mut writer = ScriptedWriter::new([WriteStep::Error]);
        let error = write_dns_tcp_payload_async(&mut writer, b"payload")
            .await
            .unwrap_err();
        assert!(error.contains("scripted"));
        assert_eq!(writer.flushes, 0);
    }
}
