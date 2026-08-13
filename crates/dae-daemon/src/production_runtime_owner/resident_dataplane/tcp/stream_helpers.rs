use super::*;
use std::io::IoSlice;
pub(in crate::production_runtime_owner::resident_dataplane) async fn open_plain_proxy_tcp_stream_async(
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
    let mut response = Vec::new();
    let mut buf = [0_u8; 256];
    loop {
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|err| format!("read http head: {err}"))?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        if let Some(index) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            let leftover = response[index + 4..].to_vec();
            response.truncate(index + 4);
            return Ok((response, leftover));
        }
        if response.len() > 8192 {
            return Err("http response header too large".to_owned());
        }
    }
    Err("incomplete http response header".to_owned())
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

#[derive(Debug, Default)]
pub(super) struct CursorBytes {
    bytes: Vec<u8>,
    offset: usize,
}

impl CursorBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset >= self.bytes.len()
    }

    fn drain_to_read_buf(&mut self, out: &mut ReadBuf<'_>) -> bool {
        if self.is_empty() || out.remaining() == 0 {
            return false;
        }
        let available = &self.bytes[self.offset..];
        let len = available.len().min(out.remaining());
        out.put_slice(&available[..len]);
        self.offset += len;
        if self.offset >= self.bytes.len() {
            self.bytes.clear();
            self.offset = 0;
        }
        true
    }
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn socks5_connect_async(
    stream: &mut TokioTcpStream,
    target: &str,
    username: &str,
    password: &str,
) -> Result<(), String> {
    time::timeout(RESIDENT_CONNECT_TIMEOUT, async {
        stream
            .write_all(&handshake::greeting(username, password))
            .await
            .map_err(|err| format!("write SOCKS5 greeting: {err}"))?;
        let mut method_selection = [0_u8; 2];
        stream
            .read_exact(&mut method_selection)
            .await
            .map_err(|err| format!("read SOCKS5 method selection: {err}"))?;
        let method = handshake::parse_method_selection(&method_selection)
            .map_err(|err| format!("parse SOCKS5 method selection: {err}"))?;
        if method == handshake::AUTH_PASSWORD {
            let auth = handshake::username_password_auth(username, password)
                .map_err(|err| format!("build SOCKS5 auth: {err}"))?;
            stream
                .write_all(&auth)
                .await
                .map_err(|err| format!("write SOCKS5 auth: {err}"))?;
            let mut auth_reply = [0_u8; 2];
            stream
                .read_exact(&mut auth_reply)
                .await
                .map_err(|err| format!("read SOCKS5 auth reply: {err}"))?;
            if auth_reply[0] != handshake::PASSWORD_AUTH_VERSION || auth_reply[1] != 0 {
                return Err(format!("SOCKS5 auth rejected: {:02x?}", auth_reply));
            }
        }
        let target =
            Socks5Address::parse(target).map_err(|err| format!("parse SOCKS5 target: {err}"))?;
        let request = handshake::request(handshake::Socks5Command::Connect, &target)
            .map_err(|err| format!("build SOCKS5 CONNECT: {err}"))?;
        stream
            .write_all(&request)
            .await
            .map_err(|err| format!("write SOCKS5 CONNECT: {err}"))?;
        let mut reply_head = [0_u8; 3];
        stream
            .read_exact(&mut reply_head)
            .await
            .map_err(|err| format!("read SOCKS5 CONNECT reply: {err}"))?;
        let mut reply = reply_head.to_vec();
        reply.extend(
            read_socks5_address_bytes_async(stream)
                .await
                .map_err(|err| err.to_string())?,
        );
        handshake::parse_server_reply(&reply)
            .map_err(|err| format!("parse SOCKS5 CONNECT reply: {err}"))?;
        Ok(())
    })
    .await
    .map_err(|_| "SOCKS5 CONNECT timeout".to_owned())?
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn http_proxy_connect_plain_async(
    stream: &mut TokioTcpStream,
    target: &str,
    username: &str,
    password: &str,
    transport: bool,
    transport_host: &str,
    transport_path: &str,
) -> Result<(), String> {
    time::timeout(RESIDENT_CONNECT_TIMEOUT, async {
        let mut options = HttpConnectOptions::connect(target);
        options.username = username.to_owned();
        options.password = password.to_owned();
        options.transport.enabled = transport;
        options.host_override = transport_host.to_owned();
        options.transport.path = transport_path.to_owned();
        let request = http_request::connect_request(&options);
        stream
            .write_all(&request)
            .await
            .map_err(|err| format!("write HTTP CONNECT request: {err}"))?;
        let response = read_plain_http_connect_head_without_overread(stream).await?;
        let status = http_request::parse_connect_response(&response)
            .map_err(|err| format!("parse HTTP CONNECT response: {err}"))?;
        if status != 200 {
            return Err(format!("HTTP CONNECT status: {status}"));
        }
        Ok(())
    })
    .await
    .map_err(|_| "HTTP CONNECT timeout".to_owned())?
}

pub(super) async fn read_socks5_address_bytes_async(
    stream: &mut TokioTcpStream,
) -> std::io::Result<Vec<u8>> {
    let mut atyp = [0_u8; 1];
    stream.read_exact(&mut atyp).await?;
    let mut out = atyp.to_vec();
    match atyp[0] {
        1 => {
            let mut rest = [0_u8; 6];
            stream.read_exact(&mut rest).await?;
            out.extend_from_slice(&rest);
        }
        3 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            out.extend_from_slice(&len);
            let mut rest = vec![0_u8; len[0] as usize + 2];
            stream.read_exact(&mut rest).await?;
            out.extend_from_slice(&rest);
        }
        4 => {
            let mut rest = [0_u8; 18];
            stream.read_exact(&mut rest).await?;
            out.extend_from_slice(&rest);
        }
        _ => {}
    }
    Ok(out)
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
