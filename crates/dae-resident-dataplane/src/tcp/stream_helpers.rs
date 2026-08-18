use super::*;
use std::io::IoSlice;
pub(crate) async fn open_plain_proxy_tcp_stream_async(
    selection: &TcpProxySelection,
) -> Result<TokioTcpStream, String> {
    open_proxy_tcp_stream_with_binding(&selection.proxy, selection.mptcp).await
}

pub(crate) async fn read_http_head_and_leftover_from_async_stream<S>(
    stream: &mut S,
) -> Result<(Vec<u8>, Vec<u8>), String>
where
    S: AsyncRead + Unpin,
{
    let result = read_http_head(
        stream,
        HttpHeadReadOptions {
            max_bytes: 8192,
            read_timeout: None,
        },
    )
    .await
    .map_err(|error| match error {
        HttpHeadReadError::Io(error) => format!("read http head: {error}"),
        HttpHeadReadError::EarlyEof => "incomplete http response header".to_owned(),
        HttpHeadReadError::TooLarge => "http response header too large".to_owned(),
        HttpHeadReadError::Timeout => "http response header timeout".to_owned(),
    })?;
    Ok((result.head, result.leftover))
}

pub(crate) fn validate_simple_obfs_http_response_status(
    response_head: &[u8],
) -> Result<(), String> {
    if validate_http_status(response_head, 200).is_ok()
        || validate_http_status(response_head, 101).is_ok()
    {
        return Ok(());
    }
    validate_http_status(response_head, 200).map_err(|err| err.to_string())
}

pub(super) async fn read_simple_obfs_tls_response_payload_from_async_stream<S>(
    stream: &mut S,
) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let mut discard = vec![0_u8; 105];
    stream
        .read_exact(&mut discard)
        .await
        .map_err(|err| format!("read simple-obfs TLS response prefix: {err}"))?;
    let mut len = [0_u8; 2];
    stream
        .read_exact(&mut len)
        .await
        .map_err(|err| format!("read simple-obfs TLS response payload length: {err}"))?;
    let payload_len = u16::from_be_bytes(len) as usize;
    // The response payload is a single TLS application-data record carrying
    // the server salt plus the first encrypted Shadowsocks AEAD chunk.  A
    // strict 16 KiB cap (the per-frame bound AsyncSimpleObfsTlsAppDataReader
    // enforces below) would reject a legitimate full-size first chunk
    // (32-byte salt + max chunk wire 2+16+16383+16 = 16449 bytes), so bound
    // by the TLS record payload ceiling instead.  This keeps a peer-controlled
    // length from forcing a large allocation or an unbounded read that would
    // pin a flow permit indefinitely.
    if payload_len > TLS_RECORD_MAX_PAYLOAD_LEN {
        return Err(format!(
            "simple-obfs TLS response payload too large: {payload_len}"
        ));
    }
    let mut payload = vec![0_u8; payload_len];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|err| format!("read simple-obfs TLS response payload: {err}"))?;
    Ok(payload)
}

#[cfg(test)]
pub(super) fn simple_obfs_tls_application_data_frame(payload: &[u8]) -> Result<Vec<u8>, String> {
    let header = simple_obfs_tls_application_data_header(payload.len())?;
    let mut out = Vec::with_capacity(header.len() + payload.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(payload);
    Ok(out)
}

pub(super) fn simple_obfs_tls_application_data_header(
    payload_len: usize,
) -> Result<[u8; 5], String> {
    let len = u16::try_from(payload_len).map_err(|_| {
        format!(
            "simple-obfs TLS application data too large: {}",
            payload_len
        )
    })?;
    let [len_high, len_low] = len.to_be_bytes();
    Ok([0x17, 0x03, 0x03, len_high, len_low])
}

pub(super) async fn write_all_vectored_header_payload(
    stream: &mut (impl AsyncWrite + Unpin),
    header: &[u8],
    payload: &[u8],
) -> std::io::Result<()> {
    if !stream.is_write_vectored() {
        let mut frame = Vec::with_capacity(header.len().saturating_add(payload.len()));
        frame.extend_from_slice(header);
        frame.extend_from_slice(payload);
        return stream.write_all(&frame).await;
    }
    let mut header_offset = 0;
    let mut payload_offset = 0;
    while header_offset < header.len() || payload_offset < payload.len() {
        let written = if header_offset < header.len() {
            stream
                .write_vectored(&[
                    IoSlice::new(&header[header_offset..]),
                    IoSlice::new(&payload[payload_offset..]),
                ])
                .await?
        } else {
            stream.write(&payload[payload_offset..]).await?
        };
        if written == 0 {
            return Err(std::io::Error::from(ErrorKind::WriteZero));
        }
        let header_remaining = header.len() - header_offset;
        let header_written = written.min(header_remaining);
        header_offset += header_written;
        payload_offset += written - header_written;
    }
    Ok(())
}

pub(super) struct AsyncPrefixTcpReader<'a, S> {
    pub(super) prefix: CursorBytes,
    pub(super) stream: &'a mut S,
}

impl<'a, S> AsyncPrefixTcpReader<'a, S> {
    pub(super) fn new(prefix: Vec<u8>, stream: &'a mut S) -> Self {
        Self {
            prefix: CursorBytes::new(prefix),
            stream,
        }
    }
}

impl<S> AsyncRead for AsyncPrefixTcpReader<'_, S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.prefix.drain_to_read_buf(buf);
        if buf.remaining() == 0 || !self.prefix.is_empty() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut *self.stream).poll_read(cx, buf)
    }
}

pub(super) struct AsyncSimpleObfsTlsAppDataReader<'a, S> {
    pub(super) prefix: CursorBytes,
    pub(super) frame: CursorBytes,
    pub(super) state: AsyncSimpleObfsTlsReadState,
    pub(super) stream: &'a mut S,
}

pub(super) enum AsyncSimpleObfsTlsReadState {
    Header { buf: [u8; 5], filled: usize },
    Payload { buf: Vec<u8>, filled: usize },
}

impl Default for AsyncSimpleObfsTlsReadState {
    fn default() -> Self {
        Self::Header {
            buf: [0_u8; 5],
            filled: 0,
        }
    }
}

impl<'a, S> AsyncSimpleObfsTlsAppDataReader<'a, S> {
    pub(super) fn new(prefix: Vec<u8>, stream: &'a mut S) -> Self {
        Self {
            prefix: CursorBytes::new(prefix),
            frame: CursorBytes::default(),
            state: AsyncSimpleObfsTlsReadState::default(),
            stream,
        }
    }
}

impl<S> AsyncRead for AsyncSimpleObfsTlsAppDataReader<'_, S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let initial_filled = out.filled().len();
        loop {
            self.prefix.drain_to_read_buf(out);
            if out.remaining() > 0 {
                self.frame.drain_to_read_buf(out);
            }
            if out.filled().len() > initial_filled || out.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }

            let state = std::mem::take(&mut self.state);
            match state {
                AsyncSimpleObfsTlsReadState::Header {
                    mut buf,
                    mut filled,
                } => {
                    while filled < buf.len() {
                        let before = filled;
                        let mut read_buf = ReadBuf::new(&mut buf[filled..]);
                        match Pin::new(&mut *self.stream).poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let read = read_buf.filled().len();
                                if read == 0 {
                                    if before == 0 {
                                        return Poll::Ready(Ok(()));
                                    }
                                    return Poll::Ready(Err(std::io::Error::new(
                                        ErrorKind::UnexpectedEof,
                                        "simple-obfs TLS application data header eof",
                                    )));
                                }
                                filled += read;
                            }
                            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                            Poll::Pending => {
                                self.state = AsyncSimpleObfsTlsReadState::Header { buf, filled };
                                return Poll::Pending;
                            }
                        }
                    }
                    if buf[..3] != [0x17, 0x03, 0x03] {
                        return Poll::Ready(Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            format!(
                                "simple-obfs TLS application data header mismatch: {:02x?}",
                                &buf[..3]
                            ),
                        )));
                    }
                    let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
                    if len > 16 * 1024 {
                        return Poll::Ready(Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            format!("simple-obfs TLS application data too large: {len}"),
                        )));
                    }
                    self.state = AsyncSimpleObfsTlsReadState::Payload {
                        buf: vec![0_u8; len],
                        filled: 0,
                    };
                }
                AsyncSimpleObfsTlsReadState::Payload {
                    mut buf,
                    mut filled,
                } => {
                    while filled < buf.len() {
                        let mut read_buf = ReadBuf::new(&mut buf[filled..]);
                        match Pin::new(&mut *self.stream).poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let read = read_buf.filled().len();
                                if read == 0 {
                                    return Poll::Ready(Err(std::io::Error::new(
                                        ErrorKind::UnexpectedEof,
                                        "simple-obfs TLS application data payload eof",
                                    )));
                                }
                                filled += read;
                            }
                            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                            Poll::Pending => {
                                self.state = AsyncSimpleObfsTlsReadState::Payload { buf, filled };
                                return Poll::Pending;
                            }
                        }
                    }
                    self.frame = CursorBytes::new(buf);
                    self.state = AsyncSimpleObfsTlsReadState::default();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generic_http_head_reader_returns_early_tunnel_bytes() {
        let (mut writer, mut reader) = tokio::io::duplex(512);
        let response =
            b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: fixture\r\n\r\nearly-tunnel";
        let write_task = tokio::spawn(async move { writer.write_all(response).await });

        let (head, leftover) = read_http_head_and_leftover_from_async_stream(&mut reader)
            .await
            .expect("generic HTTP head must parse");

        write_task.await.unwrap().unwrap();
        assert_eq!(
            head,
            b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: fixture\r\n\r\n"
        );
        assert_eq!(leftover, b"early-tunnel");
    }
}
